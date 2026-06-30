use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::fmt::{self, Display, Write};

use super::{
    args::BoundProtocolArgs,
    constructors::collect,
    typed_nodes::{
        Collect, ComputeMapping, ComputeMappingKind, ComputeScalar, ComputeScalarKind, DeserializeAndCheck,
        DirectMessage, GeneralizedNode, MergeScalars, Node, NodeId, Receive, ScalarArgument, SerializeAndSign,
        args_to_owned,
    },
    unions::{CollectArg, ComputeMappingArg, ComputeScalarArg, Dependency, DirectMessageArg, OutputNode},
};
use crate::{
    entities::{
        AnyTagRef, AssociatedData, EvidenceVerdict, FullName, MappingTag, MappingTagRef, MaybeAttributableError,
        PartyGroup, RuntimeError, ScalarTagRef, SimpleMappingFunction, SimpleScalarFunction, UnattributableError,
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

/// A union of all possible nodes.
#[derive_where::derive_where(Debug)]
pub enum AnyNode<SP: SessionParameters> {
    /// A scalar computation.
    ComputeScalar(Node<ComputeScalar<SP>>),
    /// A collection of mapping elements.
    Collect(Node<Collect<SP>>),
    /// A mapping computation.
    ComputeMapping(Node<ComputeMapping<SP>>),
    /// A serialization.
    SerializeAndSign(Node<SerializeAndSign<SP>>),
    /// A deserialization.
    DeserializeAndCheck(Node<DeserializeAndCheck<SP>>),
    /// An outgoing direct message.
    DirectMessage(Node<DirectMessage<SP>>),
    /// An expected message.
    Receive(Node<Receive<SP>>),
    /// An argument to the protocol.
    ScalarArgument(Node<ScalarArgument<SP>>),
    /// One or both scalar node results merged into one.
    MergeScalars(Node<MergeScalars<SP>>),
}

impl<SP: SessionParameters> AnyNode<SP> {
    pub(crate) fn args(&self) -> Box<dyn Iterator<Item = Self> + '_> {
        match self {
            Self::ComputeScalar(node) => Box::new(arg_map_to_any_iter(&node.as_ref().args)),
            Self::Collect(node) => Box::new(one_arg_to_any_iter(&node.as_ref().values)),
            Self::ComputeMapping(node) => match &node.as_ref().kind {
                ComputeMappingKind::Simple { .. } | ComputeMappingKind::ThirdPartyAttributable { .. } => {
                    Box::new(arg_map_to_any_iter(&node.as_ref().args))
                }
                ComputeMappingKind::WithReveal { verification_args, .. } => {
                    Box::new(arg_map_to_any_iter(&node.as_ref().args).chain(arg_map_to_any_iter(verification_args)))
                }
            },
            Self::SerializeAndSign(node) => Box::new(one_arg_to_any_iter(&node.as_ref().data)),
            Self::DeserializeAndCheck(node) => Box::new(one_arg_to_any_iter(&node.as_ref().data)),
            Self::DirectMessage(node) => Box::new(one_arg_to_any_iter(&node.as_ref().data)),
            Self::Receive(_) | Self::ScalarArgument(_) => Box::new(core::iter::empty()),
            Self::MergeScalars(node) => {
                Box::new(one_arg_to_any_iter(&node.as_ref().left).chain(one_arg_to_any_iter(&node.as_ref().right)))
            }
        }
    }

    pub(crate) fn args_and_dependencies(&self) -> Box<dyn Iterator<Item = Self> + '_> {
        Box::new(
            self.args().chain(
                self.dependencies()
                    .iter()
                    .map(GeneralizedNode::get_strong_ref)
                    .map(Self::from),
            ),
        )
    }

    pub(crate) fn store_in(&self) -> AnyTagRef<'_> {
        match self {
            Self::ComputeScalar(node) => AnyTagRef::Scalar(ScalarTagRef::Computed(&node.as_ref().store_in)),
            Self::Collect(node) => AnyTagRef::Scalar(ScalarTagRef::Collected(&node.as_ref().store_in)),
            Self::ComputeMapping(node) => AnyTagRef::Mapping(MappingTagRef::Computed(&node.as_ref().store_in)),
            Self::SerializeAndSign(node) => AnyTagRef::Mapping(MappingTagRef::LocalSigned(&node.as_ref().store_in)),
            Self::DeserializeAndCheck(node) => AnyTagRef::Mapping(MappingTagRef::Received(&node.as_ref().store_in)),
            Self::DirectMessage(node) => AnyTagRef::Mapping(MappingTagRef::Sent(&node.as_ref().store_in)),
            Self::Receive(node) => AnyTagRef::Mapping(MappingTagRef::RemoteSigned(&node.as_ref().store_in)),
            Self::ScalarArgument(node) => AnyTagRef::Scalar(ScalarTagRef::Argument(&node.as_ref().store_in)),
            Self::MergeScalars(node) => AnyTagRef::Scalar(ScalarTagRef::Merged(&node.as_ref().store_in)),
        }
    }

    pub(crate) fn dependencies(&self) -> &[Dependency<SP>] {
        match self {
            Self::ComputeScalar(node) => &node.as_ref().dependencies,
            Self::Collect(node) => &node.as_ref().dependencies,
            Self::ComputeMapping(node) => &node.as_ref().dependencies,
            Self::SerializeAndSign(node) => &node.as_ref().dependencies,
            Self::DeserializeAndCheck(node) => &node.as_ref().dependencies,
            Self::DirectMessage(node) => &node.as_ref().dependencies,
            Self::Receive(node) => &node.as_ref().dependencies,
            Self::ScalarArgument(_node) => &[],
            Self::MergeScalars(_node) => &[],
        }
    }

    fn with_replacements(self, replacements: &BTreeMap<NodeId, Self>) -> Result<Self, RuntimeError> {
        Ok(match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.with_replacements(replacements)?),
            Self::Collect(node) => Self::Collect(node.with_replacements(replacements)?),
            Self::ComputeMapping(node) => Self::ComputeMapping(node.with_replacements(replacements)?),
            Self::SerializeAndSign(node) => Self::SerializeAndSign(node.with_replacements(replacements)?),
            Self::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node.with_replacements(replacements)?),
            Self::DirectMessage(node) => Self::DirectMessage(node.with_replacements(replacements)?),
            Self::Receive(node) => Self::Receive(node.with_replacements(replacements)?),
            Self::ScalarArgument(node) => Self::ScalarArgument(node.with_replacements(replacements)?),
            Self::MergeScalars(node) => Self::MergeScalars(node.with_replacements(replacements)?),
        })
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.with_added_prefix(prefix)),
            Self::Collect(node) => Self::Collect(node.with_added_prefix(prefix)),
            Self::ComputeMapping(node) => Self::ComputeMapping(node.with_added_prefix(prefix)),
            Self::SerializeAndSign(node) => Self::SerializeAndSign(node.with_added_prefix(prefix)),
            Self::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node.with_added_prefix(prefix)),
            Self::DirectMessage(node) => Self::DirectMessage(node.with_added_prefix(prefix)),
            Self::Receive(node) => Self::Receive(node.with_added_prefix(prefix)),
            Self::ScalarArgument(node) => Self::ScalarArgument(node.with_added_prefix(prefix)),
            Self::MergeScalars(node) => Self::MergeScalars(node.with_added_prefix(prefix)),
        }
    }

    fn without_dependencies(self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.without_dependencies()),
            Self::Collect(node) => Self::Collect(node.without_dependencies()),
            Self::ComputeMapping(node) => Self::ComputeMapping(node.without_dependencies()),
            Self::SerializeAndSign(node) => Self::SerializeAndSign(node.without_dependencies()),
            Self::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node.without_dependencies()),
            Self::DirectMessage(node) => Self::DirectMessage(node.without_dependencies()),
            Self::Receive(node) => Self::Receive(node.without_dependencies()),
            Self::ScalarArgument(node) => Self::ScalarArgument(node), // Does not have dependencies
            Self::MergeScalars(node) => Self::MergeScalars(node),
        }
    }

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
                            if !function.is_reproducible() {
                                return Reproducibility::NotAvailable;
                            }
                        }
                        ComputeScalarKind::ThirdPartyAttributable { .. } => {
                            // TODO: should we have `kind.is_reproducible()`? Or defer to `function` here too
                            // instead of assuming that it will never depend on RNG?
                            // `function` here does not depend on RNG, so is always reproducible.
                        }
                    }
                }
                Self::ComputeMapping(node) => {
                    match &node.as_ref().kind {
                        ComputeMappingKind::Simple { function } => {
                            if !function.is_reproducible() {
                                return Reproducibility::NotAvailable;
                            }
                        }
                        ComputeMappingKind::WithReveal { .. } | ComputeMappingKind::ThirdPartyAttributable { .. } => {
                            // `function` here does not depend on RNG, so is always reproducible.
                        }
                    }
                }
                // This is essentially a subtype of compute-mapping with a reproducible function.
                Self::DeserializeAndCheck(_) |
                // Reproducible as long as both of its arguments are reproducible
                Self::MergeScalars(_) |
                // We can always reproduce the result of this, since it is an infallible `()`.
                Self::DirectMessage(_) => {}
                // Requires RNG and secret information (signing key), so not reproducible.
                Self::SerializeAndSign(_) => return Reproducibility::NotAvailable,
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
        let collected = collect(node, &PartyGroup::new(core::slice::from_ref(guilty_party)));

        // This is a bit of a hack.
        // To make the node tree suitable for a ruleset generation, the root node must be a scalar computation node.
        // But we cannot just assign a random name to it since there will always be a possiblity of a clash.
        // So we take the original root name (which is guaranteed to not be present in the subtree,
        // because we cannot build a reproduction subtree for a scalar node), and use it for the new root.
        let AnyTagRef::Scalar(ScalarTagRef::Computed(original_output_tag)) = self.store_in() else {
            return Err(RuntimeError::new(
                "Expected the root node to have a `ComputedScalar` tag",
            ));
        };
        let arg_name = "value";
        let guilty_party = guilty_party.clone();
        let wrapped = OutputNode::ComputeScalar(Node::new(ComputeScalar {
            store_in: original_output_tag.clone(),
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
        for node in LeavesFirstIterator::new_with_nodes(self.args_and_dependencies()) {
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

impl<SP: SessionParameters> GeneralizedNode for AnyNode<SP> {
    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Self::Collect(node) => Self::Collect(node.get_strong_ref()),
            Self::ComputeMapping(node) => Self::ComputeMapping(node.get_strong_ref()),
            Self::SerializeAndSign(node) => Self::SerializeAndSign(node.get_strong_ref()),
            Self::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node.get_strong_ref()),
            Self::DirectMessage(node) => Self::DirectMessage(node.get_strong_ref()),
            Self::Receive(node) => Self::Receive(node.get_strong_ref()),
            Self::ScalarArgument(node) => Self::ScalarArgument(node.get_strong_ref()),
            Self::MergeScalars(node) => Self::MergeScalars(node.get_strong_ref()),
        }
    }

    fn id(&self) -> NodeId {
        match self {
            Self::ComputeScalar(node) => node.id(),
            Self::Collect(node) => node.id(),
            Self::ComputeMapping(node) => node.id(),
            Self::SerializeAndSign(node) => node.id(),
            Self::DeserializeAndCheck(node) => node.id(),
            Self::DirectMessage(node) => node.id(),
            Self::Receive(node) => node.id(),
            Self::ScalarArgument(node) => node.id(),
            Self::MergeScalars(node) => node.id(),
        }
    }
}

impl<SP: SessionParameters> From<&Node<ComputeScalar<SP>>> for AnyNode<SP> {
    fn from(source: &Node<ComputeScalar<SP>>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<Node<ComputeScalar<SP>>> for AnyNode<SP> {
    fn from(source: Node<ComputeScalar<SP>>) -> Self {
        Self::ComputeScalar(source)
    }
}

impl<SP: SessionParameters> From<Node<Collect<SP>>> for AnyNode<SP> {
    fn from(source: Node<Collect<SP>>) -> Self {
        Self::Collect(source)
    }
}

impl<SP: SessionParameters> From<Node<ComputeMapping<SP>>> for AnyNode<SP> {
    fn from(source: Node<ComputeMapping<SP>>) -> Self {
        Self::ComputeMapping(source)
    }
}

impl<SP: SessionParameters> From<Node<SerializeAndSign<SP>>> for AnyNode<SP> {
    fn from(source: Node<SerializeAndSign<SP>>) -> Self {
        Self::SerializeAndSign(source)
    }
}

impl<SP: SessionParameters> From<Node<DeserializeAndCheck<SP>>> for AnyNode<SP> {
    fn from(source: Node<DeserializeAndCheck<SP>>) -> Self {
        Self::DeserializeAndCheck(source)
    }
}

impl<SP: SessionParameters> From<Node<DirectMessage<SP>>> for AnyNode<SP> {
    fn from(source: Node<DirectMessage<SP>>) -> Self {
        Self::DirectMessage(source)
    }
}

impl<SP: SessionParameters> From<Node<Receive<SP>>> for AnyNode<SP> {
    fn from(source: Node<Receive<SP>>) -> Self {
        Self::Receive(source)
    }
}

impl<SP: SessionParameters> From<Node<ScalarArgument<SP>>> for AnyNode<SP> {
    fn from(source: Node<ScalarArgument<SP>>) -> Self {
        Self::ScalarArgument(source)
    }
}

impl<SP: SessionParameters> From<ComputeScalarArg<SP>> for AnyNode<SP> {
    fn from(source: ComputeScalarArg<SP>) -> Self {
        match source {
            ComputeScalarArg::ComputeScalar(node) => Self::ComputeScalar(node),
            ComputeScalarArg::MergeScalars(node) => Self::MergeScalars(node),
            ComputeScalarArg::ScalarArgument(node) => Self::ScalarArgument(node),
            ComputeScalarArg::Collect(node) => Self::Collect(node),
        }
    }
}

impl<SP: SessionParameters> From<CollectArg<SP>> for AnyNode<SP> {
    fn from(source: CollectArg<SP>) -> Self {
        match source {
            CollectArg::ComputeMapping(node) => Self::ComputeMapping(node),
            CollectArg::SerializeAndSign(node) => Self::SerializeAndSign(node),
            CollectArg::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node),
            CollectArg::DirectMessage(node) => Self::DirectMessage(node),
            CollectArg::Receive(node) => Self::Receive(node),
        }
    }
}

impl<SP: SessionParameters> From<ComputeMappingArg<SP>> for AnyNode<SP> {
    fn from(source: ComputeMappingArg<SP>) -> Self {
        match source {
            ComputeMappingArg::ComputeScalar(node) => Self::ComputeScalar(node),
            ComputeMappingArg::MergeScalars(node) => Self::MergeScalars(node),
            ComputeMappingArg::ScalarArgument(node) => Self::ScalarArgument(node),
            ComputeMappingArg::Collect(node) => Self::Collect(node),
            ComputeMappingArg::ComputeMapping(node) => Self::ComputeMapping(node),
            ComputeMappingArg::SerializeAndSign(node) => Self::SerializeAndSign(node),
            ComputeMappingArg::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node),
        }
    }
}

impl<SP: SessionParameters> From<DirectMessageArg<SP>> for AnyNode<SP> {
    fn from(source: DirectMessageArg<SP>) -> Self {
        match source {
            DirectMessageArg::ComputeScalar(node) => Self::ComputeScalar(node),
            DirectMessageArg::ScalarArgument(node) => Self::ScalarArgument(node),
            DirectMessageArg::ComputeMapping(node) => Self::ComputeMapping(node),
            DirectMessageArg::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node),
        }
    }
}

impl<SP: SessionParameters> From<Dependency<SP>> for AnyNode<SP> {
    fn from(source: Dependency<SP>) -> Self {
        match source {
            Dependency::ComputeScalar(node) => Self::ComputeScalar(node),
            Dependency::Collect(node) => Self::Collect(node),
            Dependency::MergeScalars(node) => Self::MergeScalars(node),
        }
    }
}

impl<SP: SessionParameters> From<OutputNode<SP>> for AnyNode<SP> {
    fn from(source: OutputNode<SP>) -> Self {
        match source {
            OutputNode::ComputeScalar(node) => Self::ComputeScalar(node),
        }
    }
}

fn arg_map_to_any_iter<SP, N>(args: &BTreeMap<String, N>) -> impl Iterator<Item = AnyNode<SP>>
where
    SP: SessionParameters,
    N: GeneralizedNode,
    AnyNode<SP>: From<N>,
{
    args.values().map(|node| AnyNode::from(node.get_strong_ref()))
}

fn one_arg_to_any_iter<SP, N>(arg: &N) -> impl Iterator<Item = AnyNode<SP>>
where
    SP: SessionParameters,
    N: GeneralizedNode,
    AnyNode<SP>: From<N>,
{
    core::iter::once(AnyNode::from(arg.get_strong_ref()))
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
                node.args()
            } else {
                node.args_and_dependencies()
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
                .args_and_dependencies()
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

impl<SP: SessionParameters> Display for AnyNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::ComputeScalar(node) => write!(f, "{node}"),
            Self::Collect(node) => write!(f, "{node}"),
            Self::ComputeMapping(node) => write!(f, "{node}"),
            Self::SerializeAndSign(node) => write!(f, "{node}"),
            Self::DeserializeAndCheck(node) => write!(f, "{node}"),
            Self::DirectMessage(node) => write!(f, "{node}"),
            Self::Receive(node) => write!(f, "{node}"),
            Self::ScalarArgument(node) => write!(f, "{node}"),
            Self::MergeScalars(node) => write!(f, "{node}"),
        }
    }
}
