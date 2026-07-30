use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::fmt::Write;

use super::{
    any_node::AnyNode,
    args::BoundProtocolArgs,
    constructors::collect,
    specific_nodes::{
        ComputeMapping, ComputeMappingKind, ComputeScalar, ComputeScalarKind, GeneralizedNode, Node, NodeId,
        args_to_owned,
    },
    union_nodes::{CollectArg, ComputeScalarArg, OutputNode},
};
use crate::{
    entities::{
        AnyTagRef, AssociatedData, ComputedScalarTag, EvidenceVerdict, FullName, MappingTag, MaybeAttributableError,
        RuntimeError, SimpleMappingFunction, SimpleScalarFunction, ThresholdGroup, UnattributableError,
        UnattributableMappingFunction, UnattributableScalarFunction, Value,
    },
    traced_error::TraceableResult,
    traits::SessionParameters,
};

#[derive(Debug)]
pub(crate) enum Reproducibility {
    Available {
        arguments: BTreeSet<String>,
        messages: BTreeSet<FullName>,
    },
    NotAvailable,
}

impl<SP: SessionParameters> AnyNode<SP> {
    /// Pretty prints the node tree.
    #[must_use]
    pub fn display_tree(&self) -> String {
        let mut s = String::new();
        for node in self.flattened_leaves_first() {
            writeln!(&mut s, "{node}").expect("Display impl for a Node is infallible");
        }
        s
    }

    fn is_local(&self) -> bool {
        for node in self.flattened_args_only() {
            if matches!(node, Self::Receive(_)) {
                return false;
            }
        }
        true
    }

    /// If the node is reproducible in the evidence verification setting
    /// (where we only know the protocol's shared public data),
    /// returns a `Reproducibility::Available` with the required arguments and messages.
    /// Otherwise, returns a `Reproducibility::NoteAvailable`.
    pub(crate) fn reproducibility(&self) -> Reproducibility {
        let mut arguments = BTreeSet::<String>::new();
        let mut messages = BTreeSet::<FullName>::new();

        let subnodes = if let Self::ComputeMapping(node) = self
            && let ComputeMappingKind::WithReveal { verification_args, .. } = &node.as_ref().kind
        {
            let args = verification_args
                .values()
                .map(GeneralizedNode::get_strong_ref)
                .map(Self::from);
            UnorderedIterator::new_with_nodes(args, true)
        } else {
            self.flattened_args_only()
        };

        for node in subnodes {
            match node {
                Self::ComputeScalar(node) => {
                    match &node.as_ref().kind {
                        ComputeScalarKind::Simple { function } => {
                            if !function.is_deterministic() {
                                return Reproducibility::NotAvailable;
                            }
                        }
                        ComputeScalarKind::ThirdPartyAttributable { .. } => {
                            // Verification functions do not depend on RNG, so they are always reproducible.
                        }
                    }
                }
                Self::ComputeMapping(node) => {
                    match &node.as_ref().kind {
                        ComputeMappingKind::Simple { function } => {
                            if !function.is_deterministic() {
                                return Reproducibility::NotAvailable;
                            }
                        }
                        ComputeMappingKind::WithReveal { .. } | ComputeMappingKind::ThirdPartyAttributable { .. } => {
                            // Verification functions do not depend on RNG, so they are always reproducible.
                        }
                    }
                }
                // This is essentially a subtype of compute-mapping with a reproducible function.
                Self::DeserializeAndCheck(_) |
                // Reproducible as long as both of its arguments are reproducible
                Self::MergeScalars(_) |
                // We can always reproduce the result of this, since it is an infallible `()`.
                Self::SendDM(_) | Self::SendBC(_) | Self::SendAll(_) => {}
                // Requires RNG and secret information (signing key), so not reproducible.
                Self::SerializeAndSignBC(_) | Self::SerializeAndSignDM(_) => return Reproducibility::NotAvailable,
                Self::Collect(_) => {
                    // If a collection does not entirely depend on local data,
                    // it will need messages from different nodes to be reproduced.
                    if !node.is_local() {
                        return Reproducibility::NotAvailable;
                    }
                }
                Self::Receive(node) => {
                    messages.insert(node.as_ref().message_name.clone());
                }
                Self::ScalarArgument(node) => {
                    arguments.insert(node.as_ref().name.clone());
                }
            }
        }

        Reproducibility::Available { arguments, messages }
    }

    fn flattened(&self) -> UnorderedIterator<SP> {
        UnorderedIterator::new(self, false)
    }

    fn flattened_args_only(&self) -> UnorderedIterator<SP> {
        UnorderedIterator::new(self, true)
    }

    /// Returns the nodes in topological order.
    ///
    /// That is, every node will come prior to its dependencies.
    pub(crate) fn flattened_roots_first(&self) -> Vec<Self> {
        // Reusing the reverse topological sort logic for simplicity.
        // Can use a dedicated algorithm (e.g. Kahn's) if it becomes a bottleneck.
        let mut ordered = self.flattened_leaves_first().collect::<Vec<_>>();
        ordered.reverse();
        ordered
    }

    pub(crate) fn flattened_leaves_first(&self) -> LeavesFirstIterator<SP> {
        LeavesFirstIterator::new(self)
    }

    pub(crate) fn find_subnode(&self, tag: AnyTagRef<'_>) -> Option<Self> {
        self.flattened()
            .find(|subnode| subnode.store_in() == tag)
            .map(|node| node.get_strong_ref())
    }

    fn tree_without_dependencies(&self) -> Self {
        self.mutated_tree(|node| Ok(node.without_dependencies()))
            .expect("the closure is infallible")
    }

    pub(crate) fn get_reproduction_subtree(
        &self,
        tag: &MappingTag,
        guilty_party: &SP::Verifier,
        associated_data: Option<&AssociatedData<SP>>,
    ) -> Result<OutputNode<SP>, RuntimeError> {
        let node = self
            .find_subnode(AnyTagRef::Mapping(tag.as_ref()))
            .ok_or_else(|| RuntimeError::new(format!("Node {tag} was not found")))?;

        let node = if let Some(associated_data) = associated_data
            && let Self::ComputeMapping(node) = &node
            && let ComputeMappingKind::WithReveal {
                verification,
                verification_args,
                ..
            } = &node.as_ref().kind
        {
            let associated_data = associated_data.clone();
            let verification = verification.clone();
            Self::from(Node::new(ComputeMapping {
                store_in: node.as_ref().store_in.clone(),
                kind: ComputeMappingKind::Simple {
                    function: SimpleMappingFunction::Unattributable(UnattributableMappingFunction::new_with_name(
                        "<associated_verification>",
                        move |id, args| Ok(Value::new(verification.call(id, args, &associated_data)?)),
                    )),
                },
                args: args_to_owned(verification_args),
                dependencies: Vec::new(),
            }))
        } else if associated_data.is_none()
            && let Self::ComputeMapping(node) = node
            && let ComputeMappingKind::Simple { function } = &node.as_ref().kind
            && let SimpleMappingFunction::SenderAttributable(function) = function
        {
            let function = function.clone();
            Self::from(Node::new(ComputeMapping {
                store_in: node.as_ref().store_in.clone(),
                kind: ComputeMappingKind::Simple {
                    function: SimpleMappingFunction::Unattributable(UnattributableMappingFunction::new_with_name(
                        "<node_itself_as_verification>",
                        move |id, args| {
                            match function.call(id, args) {
                                Ok(_) => Ok(EvidenceVerdict::invalid("The target function finished successfully")),
                                Err(MaybeAttributableError::Attributable { .. }) => Ok(EvidenceVerdict::valid()),
                                Err(MaybeAttributableError::Runtime(error)) => Err(UnattributableError::Runtime(error)),
                            }
                            .map(Value::new)
                        },
                    )),
                },
                args: args_to_owned(&node.as_ref().args),
                dependencies: Vec::new(),
            }))
        } else {
            return Err(RuntimeError::new("Unexpected node type"));
        };

        let node =
            CollectArg::try_from(node.tree_without_dependencies()).expect("the node is convertible to CollectArg");

        // The output must be a scalar node, and `node` is a mapping node.
        // So we wrap it in a collect.
        let collected = collect(node, &ThresholdGroup::new(&BTreeSet::from([guilty_party.clone()])));

        // This is a bit of a hack.
        // To make the node tree suitable for a ruleset generation, the root node must be a scalar computation node.
        // But we cannot just assign a random name to it since there will always be a possiblity of a clash.
        // So we take the original root name (which is guaranteed to not be present in the subtree,
        // because we cannot build a reproduction subtree for a scalar node), and use it for the new root.
        let Ok(original_output_tag) = ComputedScalarTag::try_from(self.store_in().to_owned()) else {
            return Err(RuntimeError::new(
                "Expected the root node to have a `ComputedScalar` tag",
            ));
        };
        let arg_name = "value";
        let guilty_party = guilty_party.clone();
        let wrapped = OutputNode::ComputeScalar(Node::new(ComputeScalar {
            store_in: original_output_tag,
            kind: ComputeScalarKind::Simple {
                function: SimpleScalarFunction::Unattributable(UnattributableScalarFunction::new_with_name(
                    "<evidence_verification_output>",
                    move |args| {
                        let map = args.get_map::<EvidenceVerdict>(arg_name)?;
                        let verdict: &EvidenceVerdict = map
                            .get(&guilty_party)
                            .ok_or_else(|| RuntimeError::new("Guilty party entry not found"))?;
                        Ok(Value::new(verdict.clone()))
                    },
                )),
            },
            args: [(arg_name.into(), ComputeScalarArg::Collect(collected.get_strong_ref()))].into(),
            dependencies: Vec::new(),
        }));

        Ok(wrapped)
    }

    fn mutated_tree(&self, f: impl Fn(Self) -> Result<Self, RuntimeError>) -> Result<Self, RuntimeError> {
        let mut replacement_nodes = BTreeMap::new();

        // The root node will be processed separately
        for node in LeavesFirstIterator::new_with_nodes(self.all_args_and_dependencies()) {
            let old_id = node.id();
            let store_in = node.store_in().to_owned();
            let new_node = f(node)
                .or_with_context(|| format!("Failed to apply predicate to the node {store_in}"))?
                .with_replacements(&replacement_nodes)?;
            // Note that this may lead to errors if the node with `old_id` is dropped,
            // but we are still retaining `self`, so all of its tree will persist until the end of the method.
            if new_node.id() != old_id {
                replacement_nodes.insert(old_id, new_node);
            }
        }

        f(self.get_strong_ref())
            .or_with_context(|| format!("Failed to apply predicate to the root node {}", self.store_in()))?
            .with_replacements(&replacement_nodes)
    }

    pub(crate) fn tree_with_added_prefix(&self, prefix: &str) -> Self {
        self.mutated_tree(|node| Ok(node.with_added_prefix(prefix)))
            .expect("the closure is infallible")
    }

    pub(crate) fn with_substituted_arguments(&self, arguments: &BoundProtocolArgs<SP>) -> Result<Self, RuntimeError> {
        self.mutated_tree(|node| {
            Ok(if let Self::ScalarArgument(node) = node {
                arguments.get(&node.as_ref().name)?.get_strong_ref()
            } else {
                node
            })
        })
    }

    #[cfg(feature = "dev")]
    pub(crate) fn with_replaced_subnode(&self, old_subnode: &Self, new_subnode: &Self) -> Self {
        self.mutated_tree(|node| {
            Ok(if node.id() == old_subnode.id() {
                new_subnode.get_strong_ref()
            } else {
                node
            })
        })
        .expect("the closure is infallible")
    }
}

/// Iterates over the node subtree in unspecified order.
///
/// Guaranteed to only emit each node once.
pub(crate) struct UnorderedIterator<SP: SessionParameters> {
    queue: Vec<AnyNode<SP>>,
    emitted: BTreeSet<NodeId>,
    args_only: bool,
}

impl<SP: SessionParameters> UnorderedIterator<SP> {
    fn new(root: &AnyNode<SP>, args_only: bool) -> Self {
        Self::new_with_nodes(core::iter::once(root.get_strong_ref()), args_only)
    }

    fn new_with_nodes(roots: impl Iterator<Item = AnyNode<SP>>, args_only: bool) -> Self {
        Self {
            queue: roots.collect(),
            emitted: BTreeSet::new(),
            args_only,
        }
    }
}

impl<SP: SessionParameters> Iterator for UnorderedIterator<SP> {
    type Item = AnyNode<SP>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(node) = self.queue.pop() {
            let children = if self.args_only {
                node.all_args()
            } else {
                node.all_args_and_dependencies()
            };
            for child_node in children {
                if !self.emitted.contains(&child_node.id()) {
                    self.queue.push(child_node);
                }
            }
            self.emitted.insert(node.id());
            return Some(node);
        }
        None
    }
}

/// Iterates over the node subtree including the root node in reverse topological order.
///
/// That is, the nodes are emitted in such a way that for every node all its dependencies preceed it.
pub(crate) struct LeavesFirstIterator<SP: SessionParameters> {
    queue: Vec<AnyNode<SP>>,
    emitted: BTreeSet<NodeId>,
}

impl<SP: SessionParameters> LeavesFirstIterator<SP> {
    fn new(root: &AnyNode<SP>) -> Self {
        Self {
            queue: vec![root.get_strong_ref()],
            emitted: BTreeSet::new(),
        }
    }

    fn new_with_nodes(roots: impl Iterator<Item = AnyNode<SP>>) -> Self {
        Self {
            queue: roots.collect(),
            emitted: BTreeSet::new(),
        }
    }
}

impl<SP: SessionParameters> Iterator for LeavesFirstIterator<SP> {
    type Item = AnyNode<SP>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.queue.pop() {
            if self.emitted.contains(&node.id()) {
                continue;
            }

            let unprocessed_children = node
                .all_args_and_dependencies()
                .filter_map(|child_node| {
                    let id = child_node.id();
                    if self.emitted.contains(&id) {
                        None
                    } else {
                        Some(child_node.get_strong_ref())
                    }
                })
                .collect::<Vec<_>>();

            if unprocessed_children.is_empty() {
                self.emitted.insert(node.id());
                return Some(node);
            }

            self.queue.push(node.get_strong_ref());
            // Note that this may push some nodes that are already in the queue (if they had multiple parents).
            // We will pop the last pushed instance first, so it is guaranteed to be emitted before any of its parents,
            // and the rest will be skipped by the condition at the start of the loop.
            self.queue.extend(unprocessed_children);
        }
        None
    }
}
