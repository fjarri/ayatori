use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Write},
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::fmt::Debug;

use itertools::Itertools;

use super::args::BoundProtocolArgs;
use crate::{
    entities::{
        AnyTagRef, DeserializeFunction, FullName, MappingFunction, MappingTag, PartyGroup, ScalarFunction, ScalarTag,
        SerdeAdapter, SerializeAndSignFunction,
    },
    errors::LocalError,
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

// `Node` intentionally does not implement `Clone` - our clones are shallow, which may be confusing for the user.
#[derive(Debug)]
pub struct Node<SP: SessionParameters>(Arc<TypedNode<SP>>);

impl<SP: SessionParameters> Node<SP> {
    fn new_typed(typed_node: TypedNode<SP>) -> Self {
        Self(Arc::new(typed_node))
    }

    pub(crate) fn new(kind: NodeKind<SP>) -> Self {
        Self::new_typed(TypedNode::new(kind))
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.0.group()
    }

    pub fn with_dependencies(self, dependencies: &[&Self]) -> Result<Self, LocalError> {
        if !dependencies.iter().all(|node| node.group().is_none()) {
            return Err(LocalError::new("Dependencies must be scalar nodes"));
        }
        Ok(Self::new_typed(
            self.unwrap_or_shallow_clone().with_dependencies(dependencies),
        ))
    }

    pub(crate) fn get_strong_ref(&self) -> Self {
        Self(self.0.clone())
    }

    /// NOTE: use with care. If a node is dropped and another one is created, it may get the same ID.
    fn id(&self) -> usize {
        // A little hacky. Is there a better way?
        Arc::as_ptr(&self.0) as usize
    }

    pub(crate) fn store_in(&self) -> AnyTagRef<'_> {
        self.0.store_in()
    }

    pub(crate) fn store_in_and_group(&self) -> Option<(&MappingTag, &PartyGroup<SP::Verifier>)> {
        self.0.kind().store_in_and_group()
    }

    pub(crate) fn dependencies(&self) -> &[Node<SP>] {
        self.0.dependencies()
    }

    pub(crate) fn kind(&self) -> &NodeKind<SP> {
        self.0.kind()
    }

    fn unwrap_or_shallow_clone(self) -> TypedNode<SP> {
        Arc::try_unwrap(self.0).unwrap_or_else(|arc| arc.shallow_clone())
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, Node<SP>>) -> Node<SP> {
        Self::new_typed(self.unwrap_or_shallow_clone().with_replacements(replacements))
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        Self::new_typed(self.unwrap_or_shallow_clone().with_added_prefix(prefix))
    }

    pub fn display_tree(&self) -> String {
        let mut s = String::new();
        for node in self.flattened() {
            writeln!(&mut s, "{node}").expect("Display impl for a Node is infallible");
        }
        s
    }

    pub(crate) fn get_reproduction_subtree(
        &self,
        tag: &MappingTag,
        verifier: &SP::Verifier,
    ) -> Result<Self, LocalError> {
        let node = self
            .find_subnode(AnyTagRef::Mapping(tag))
            .ok_or_else(|| LocalError::new(format!("Node {tag} was not found")))?;
        let node = node.tree_without_dependencies();

        // The output must be a scalar node, and `node` is an mapping node.
        // So we wrap it in a collection node.
        let wrapped = Node::new(NodeKind::Collect {
            store_in: tag.collected(),
            values: node.get_strong_ref(),
            group: PartyGroup::new(core::slice::from_ref(verifier)),
        });

        Ok(wrapped)
    }

    fn is_local(&self) -> bool {
        for node in self.flattened_args() {
            if matches!(node.kind(), NodeKind::Receive { .. }) {
                return false;
            }
        }
        true
    }

    pub(crate) fn reproducibility(&self) -> Reproducibility {
        let mut arguments = BTreeSet::<String>::new();
        let mut messages = BTreeSet::<FullName>::new();

        for node in self.flattened_args() {
            match node.kind() {
                NodeKind::ComputeScalar { function, .. } => {
                    if !function.is_reproducible() {
                        return Reproducibility::NotAvailable;
                    }
                }
                NodeKind::ComputeMapping { function, .. } => {
                    if !function.is_reproducible() {
                        return Reproducibility::NotAvailable;
                    }
                }
                // Requires RNG and secret information (signing key), so not reproducible.
                NodeKind::SerializeAndSign { .. } => return Reproducibility::NotAvailable,
                // This is essentially a subtype of compute-mapping with a reproducible function.
                NodeKind::Deserialize { .. } => {}
                // We can always reproduce the result of this, since it is an infallible `()`.
                NodeKind::DirectMessage { .. } => {}
                NodeKind::Collect { .. } => {
                    // If a collection does not entirely depend on local data,
                    // it will need messages from different nodes to be reproduced.
                    if !node.is_local() {
                        return Reproducibility::NotAvailable;
                    }
                }
                NodeKind::Receive { message_name, .. } => {
                    messages.insert(message_name.clone());
                }
                NodeKind::ScalarArgument { name, .. } => {
                    arguments.insert(name.clone());
                }
            }
        }

        Reproducibility::Available { arguments, messages }
    }

    pub(crate) fn flattened(&self) -> TreeIterator<SP> {
        TreeIterator::new(self, false)
    }

    pub(crate) fn flattened_args(&self) -> TreeIterator<SP> {
        TreeIterator::new(self, true)
    }

    pub(crate) fn find_subnode(&self, tag: AnyTagRef<'_>) -> Option<Self> {
        self.flattened()
            .find(|subnode| subnode.store_in() == tag)
            .map(|node| node.get_strong_ref())
    }

    fn without_dependencies(self) -> Self {
        Self::new_typed(self.unwrap_or_shallow_clone().without_dependencies())
    }

    fn tree_without_dependencies(&self) -> Self {
        self.mutate_tree(|node| Ok(node.without_dependencies()))
            .expect("the closure is infallible")
    }

    pub(crate) fn with_substituted_arguments(&self, arguments: BoundProtocolArgs<SP>) -> Result<Self, LocalError> {
        self.mutate_tree(|node| {
            Ok(if let NodeKind::ScalarArgument { name, .. } = node.kind() {
                arguments.get(name)?.get_strong_ref()
            } else {
                node
            })
        })
    }

    #[cfg(any(test, feature = "dev"))]
    pub(crate) fn with_replaced_subnode(&self, old_subnode: &Self, new_subnode: &Self) -> Self {
        self.mutate_tree(|node| {
            Ok(if node.id() == old_subnode.id() {
                new_subnode.get_strong_ref()
            } else {
                node
            })
        })
        .expect("the closure is infallible")
    }

    pub(crate) fn tree_with_added_prefix(&self, prefix: &str) -> Self {
        self.mutate_tree(|node| Ok(node.with_added_prefix(prefix)))
            .expect("the closure is infallible")
    }

    fn mutate_tree(&self, f: impl Fn(Self) -> Result<Self, LocalError>) -> Result<Self, LocalError> {
        let mut replacement_nodes = BTreeMap::new();

        for node in self.flattened() {
            if node.id() == self.id() {
                // This is the last element of the iterator, and we will process it separately.
                break;
            }
            let old_id = node.id();
            let new_node = f(node)?.with_replacements(&replacement_nodes);
            // Note that this may lead to errors if the node with `old_id` is dropped,
            // but we are still retaining `self`, so all of its tree will persist until the end of the method.
            if new_node.id() != old_id {
                replacement_nodes.insert(old_id, new_node);
            }
        }

        Ok(f(self.get_strong_ref())?.with_replacements(&replacement_nodes))
    }
}

/// Iterates over the node subtree including the root node depth-first.
/// That is, the nodes are emitted in such a way that for every node all its dependencies preceed it.
pub(crate) struct TreeIterator<SP: SessionParameters> {
    queue: Vec<Node<SP>>,
    seen: BTreeSet<usize>,
    args_only: bool,
}

impl<SP: SessionParameters> TreeIterator<SP> {
    fn new(root: &Node<SP>, args_only: bool) -> Self {
        Self {
            queue: vec![root.get_strong_ref()],
            seen: BTreeSet::new(),
            args_only,
        }
    }
}

impl<SP: SessionParameters> Iterator for TreeIterator<SP> {
    type Item = Node<SP>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.queue.pop() {
            let all_dependencies = if self.args_only {
                node.kind().args()
            } else {
                Box::new(node.dependencies().iter().chain(node.kind().args()))
            };

            let unprocessed_dependencies = all_dependencies
                .filter_map(|dependency| {
                    let id = dependency.id();
                    if self.seen.contains(&id) {
                        None
                    } else {
                        Some(dependency.get_strong_ref())
                    }
                })
                .collect::<Vec<_>>();

            if unprocessed_dependencies.is_empty() {
                self.seen.insert(node.id());
                return Some(node);
            }

            self.queue.push(node.get_strong_ref());
            self.queue.extend(unprocessed_dependencies.into_iter());
        }
        None
    }
}

impl<SP: SessionParameters> Display for Node<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0.as_ref())
    }
}

#[derive(Debug)]
struct TypedNode<SP: SessionParameters> {
    kind: NodeKind<SP>,
    dependencies: Vec<Node<SP>>,
}

impl<SP: SessionParameters> TypedNode<SP> {
    fn new(kind: NodeKind<SP>) -> Self {
        Self {
            kind,
            dependencies: Vec::new(),
        }
    }

    fn store_in(&self) -> AnyTagRef<'_> {
        self.kind.store_in()
    }

    fn dependencies(&self) -> &[Node<SP>] {
        &self.dependencies
    }

    fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.kind.group()
    }

    fn kind(&self) -> &NodeKind<SP> {
        &self.kind
    }

    #[must_use]
    fn with_dependencies(self, dependencies: &[&Node<SP>]) -> Self {
        let mut new_node = self;
        new_node
            .dependencies
            .extend(dependencies.iter().map(|dependency| dependency.get_strong_ref()));
        new_node
    }

    fn without_dependencies(self) -> Self {
        let mut new_node = self;
        new_node.dependencies = Vec::new();
        new_node
    }

    fn shallow_clone(&self) -> Self {
        Self {
            dependencies: nodes_to_owned(self.dependencies.iter()),
            kind: self.kind.shallow_clone(),
        }
    }

    fn with_replacements(self, replacements: &BTreeMap<usize, Node<SP>>) -> Self {
        let mut new_node = self;
        maybe_replace_slice(&mut new_node.dependencies, replacements);
        new_node.kind.replace(replacements);
        new_node
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut new_node = self;
        new_node.kind = new_node.kind.with_added_prefix(prefix);
        new_node
    }
}

impl<SP: SessionParameters> Display for TypedNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{} = {}", self.store_in(), self.kind)?;
        if !self.dependencies.is_empty() {
            write!(
                f,
                " <- {}",
                self.dependencies
                    .iter()
                    .map(|dependency| dependency.store_in().to_string())
                    .join(", ")
            )?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum NodeKind<SP: SessionParameters> {
    ComputeScalar {
        store_in: ScalarTag,
        function: ScalarFunction<SP>,
        args: BTreeMap<String, Node<SP>>,
    },
    ComputeMapping {
        store_in: MappingTag,
        function: MappingFunction<SP>,
        group: PartyGroup<SP::Verifier>,
        args: BTreeMap<String, Node<SP>>,
    },
    SerializeAndSign {
        store_in: MappingTag,
        function: SerializeAndSignFunction<SP>,
        data: Node<SP>,
        group: PartyGroup<SP::Verifier>,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        message_name: FullName,
    },
    Deserialize {
        store_in: MappingTag,
        function: DeserializeFunction<SP>,
        data: Node<SP>,
        group: PartyGroup<SP::Verifier>,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
    },
    DirectMessage {
        store_in: MappingTag,
        data: Node<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Collect {
        store_in: ScalarTag,
        values: Node<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Receive {
        store_in: MappingTag,
        group: PartyGroup<SP::Verifier>,
        message_name: FullName,
    },
    ScalarArgument {
        store_in: ScalarTag,
        name: String,
    },
}

impl<SP: SessionParameters> Display for NodeKind<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::ComputeScalar {
                store_in: _store_in,
                function,
                args,
            } => {
                write!(
                    f,
                    "{function}({})",
                    args.iter()
                        .map(|(name, arg)| format!("{}={}", name, arg.store_in()))
                        .join(", ")
                )
            }
            Self::ComputeMapping {
                store_in: _store_in,
                function,
                group: _group,
                args,
            } => {
                write!(
                    f,
                    "{function}[]({})",
                    args.iter()
                        .map(|(name, arg)| format!("{}={}", name, arg.store_in()))
                        .join(", ")
                )
            }
            Self::SerializeAndSign { data, .. } => {
                write!(f, "serialize_and_sign[]({})", data.store_in())
            }
            Self::Deserialize { data, .. } => {
                write!(f, "deserialize[]({})", data.store_in())
            }
            Self::DirectMessage {
                store_in: _store_in,
                data,
                group: _group,
            } => {
                write!(f, "direct_message({})", data.store_in())
            }
            Self::Collect {
                store_in: _store_in,
                values,
                group: _group,
            } => {
                write!(f, "collect({})", values.store_in())
            }
            Self::Receive {
                store_in: _store_in,
                group: _group,
                message_name: _message_name,
            } => write!(f, "receive()"),
            Self::ScalarArgument {
                store_in: _store_in,
                name,
            } => write!(f, "argument({name})"),
        }
    }
}

impl<SP: SessionParameters> NodeKind<SP> {
    fn store_in(&self) -> AnyTagRef<'_> {
        match self {
            Self::ComputeScalar { store_in, .. }
            | Self::Collect { store_in, .. }
            | Self::ScalarArgument { store_in, .. } => AnyTagRef::Scalar(store_in),
            Self::ComputeMapping { store_in, .. }
            | Self::SerializeAndSign { store_in, .. }
            | Self::Deserialize { store_in, .. }
            | Self::DirectMessage { store_in, .. }
            | Self::Receive { store_in, .. } => AnyTagRef::Mapping(store_in),
        }
    }

    fn store_in_and_group(&self) -> Option<(&MappingTag, &PartyGroup<SP::Verifier>)> {
        match self {
            Self::ComputeMapping { store_in, group, .. }
            | Self::SerializeAndSign { store_in, group, .. }
            | Self::Deserialize { store_in, group, .. }
            | Self::DirectMessage { store_in, group, .. }
            | Self::Receive { store_in, group, .. } => Some((store_in, group)),
            Self::Collect { .. } | Self::ComputeScalar { .. } | Self::ScalarArgument { .. } => None,
        }
    }

    fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        match self {
            Self::ComputeMapping { group, .. }
            | Self::SerializeAndSign { group, .. }
            | Self::Deserialize { group, .. }
            | Self::DirectMessage { group, .. }
            | Self::Receive { group, .. } => Some(group),
            Self::Collect { .. } | Self::ComputeScalar { .. } | Self::ScalarArgument { .. } => None,
        }
    }

    fn shallow_clone(&self) -> Self {
        match self {
            Self::ComputeScalar {
                store_in,
                function,
                args,
            } => Self::ComputeScalar {
                store_in: store_in.clone(),
                function: function.clone(),
                args: arg_map_to_owned(args),
            },
            Self::ComputeMapping {
                store_in,
                function,
                group,
                args,
            } => Self::ComputeMapping {
                store_in: store_in.clone(),
                function: function.clone(),
                group: group.clone(),
                args: arg_map_to_owned(args),
            },
            Self::SerializeAndSign {
                store_in,
                function,
                data,
                group,
                message_name,
                serde_adapter,
            } => Self::SerializeAndSign {
                store_in: store_in.clone(),
                function: function.clone(),
                data: data.get_strong_ref(),
                group: group.clone(),
                message_name: message_name.clone(),
                serde_adapter: serde_adapter.clone(),
            },
            Self::Deserialize {
                store_in,
                function,
                data,
                group,
                serde_adapter,
            } => Self::Deserialize {
                store_in: store_in.clone(),
                function: function.clone(),
                data: data.get_strong_ref(),
                group: group.clone(),
                serde_adapter: serde_adapter.clone(),
            },
            Self::DirectMessage { store_in, data, group } => Self::DirectMessage {
                store_in: store_in.clone(),
                data: data.get_strong_ref(),
                group: group.clone(),
            },
            Self::Collect {
                store_in,
                values,
                group,
            } => Self::Collect {
                store_in: store_in.clone(),
                values: values.get_strong_ref(),
                group: group.clone(),
            },
            Self::Receive {
                store_in,
                group,
                message_name,
            } => Self::Receive {
                store_in: store_in.clone(),
                group: group.clone(),
                message_name: message_name.clone(),
            },
            Self::ScalarArgument { store_in, name } => Self::ScalarArgument {
                store_in: store_in.clone(),
                name: name.clone(),
            },
        }
    }

    fn args(&self) -> Box<dyn Iterator<Item = &Node<SP>> + '_> {
        match self {
            Self::ComputeScalar { args, .. } | Self::ComputeMapping { args, .. } => Box::new(args.values()),
            Self::SerializeAndSign { data, .. } => Box::new(core::iter::once(data)),
            Self::Deserialize { data, .. } => Box::new(core::iter::once(data)),
            Self::Collect { values, .. } => Box::new(core::iter::once(values)),
            Self::DirectMessage { data, .. } => Box::new(core::iter::once(data)),
            Self::Receive { .. } => Box::new(core::iter::empty()),
            Self::ScalarArgument { .. } => Box::new(core::iter::empty()),
        }
    }

    fn replace(&mut self, replacements: &BTreeMap<usize, Node<SP>>) {
        match self {
            Self::ComputeScalar { args, .. } => maybe_replace_map(args, replacements),
            Self::ComputeMapping { args, .. } => maybe_replace_map(args, replacements),
            Self::SerializeAndSign { data, .. } => maybe_replace(data, replacements),
            Self::Deserialize { data, .. } => maybe_replace(data, replacements),
            Self::Collect { values, .. } => maybe_replace(values, replacements),
            Self::DirectMessage { data, .. } => maybe_replace(data, replacements),
            Self::Receive { .. } | Self::ScalarArgument { .. } => {}
        }
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut result = self;
        match &mut result {
            Self::ComputeScalar { store_in, .. }
            | Self::ScalarArgument { store_in, .. }
            | Self::Collect { store_in, .. } => {
                *store_in = store_in.clone().with_added_prefix(prefix);
            }
            Self::ComputeMapping { store_in, .. } | Self::DirectMessage { store_in, .. } => {
                *store_in = store_in.clone().with_added_prefix(prefix);
            }
            Self::SerializeAndSign {
                store_in, message_name, ..
            } => {
                *store_in = store_in.clone().with_added_prefix(prefix);
                *message_name = message_name.clone().with_added_prefix(prefix);
            }
            Self::Deserialize { store_in, .. } => {
                *store_in = store_in.clone().with_added_prefix(prefix);
            }
            Self::Receive {
                store_in, message_name, ..
            } => {
                *store_in = store_in.clone().with_added_prefix(prefix);
                *message_name = message_name.clone().with_added_prefix(prefix);
            }
        };
        result
    }
}

pub(crate) fn arg_map_to_owned<SP: SessionParameters>(args: &BTreeMap<String, Node<SP>>) -> BTreeMap<String, Node<SP>> {
    args.iter()
        .map(|(name, node)| (name.clone(), node.get_strong_ref()))
        .collect()
}

pub(crate) fn args_to_owned<'a, SP: SessionParameters>(
    nodes: impl Iterator<Item = (&'a str, &'a Node<SP>)>,
) -> Result<BTreeMap<String, Node<SP>>, LocalError> {
    let mut result = BTreeMap::new();
    for (name, node) in nodes {
        if result.contains_key(name) {
            return Err(LocalError::new(format!("Repeating argument name: {name}")));
        }
        result.insert(name.into(), node.get_strong_ref());
    }
    Ok(result)
}

pub(crate) fn nodes_to_owned<'a, SP: SessionParameters>(nodes: impl Iterator<Item = &'a Node<SP>>) -> Vec<Node<SP>> {
    nodes.map(|node| node.get_strong_ref()).collect()
}

fn maybe_replace<SP: SessionParameters>(node: &mut Node<SP>, replacements: &BTreeMap<usize, Node<SP>>) {
    if let Some(replacement) = replacements.get(&node.id()) {
        *node = replacement.get_strong_ref()
    }
}

fn maybe_replace_slice<SP: SessionParameters>(nodes: &mut [Node<SP>], replacements: &BTreeMap<usize, Node<SP>>) {
    for node in nodes {
        maybe_replace(node, replacements)
    }
}

fn maybe_replace_map<SP: SessionParameters>(
    nodes: &mut BTreeMap<String, Node<SP>>,
    replacements: &BTreeMap<usize, Node<SP>>,
) {
    for node in nodes.values_mut() {
        maybe_replace(node, replacements)
    }
}
