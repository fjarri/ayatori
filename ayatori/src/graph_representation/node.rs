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

    pub fn with_dependencies(self, dependencies: &[&Self]) -> Result<Self, LocalError> {
        if !dependencies.iter().all(|node| node.store_in().scalar().is_some()) {
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
        for node in self.flattened_leaves_first() {
            writeln!(&mut s, "{node}").expect("Display impl for a Node is infallible");
        }
        s
    }

    pub(crate) fn get_reproduction_subtree(
        &self,
        tag: &MappingTag,
        guilty_party: &SP::Verifier,
    ) -> Result<Self, LocalError> {
        let node = self
            .find_subnode(AnyTagRef::Mapping(tag))
            .ok_or_else(|| LocalError::new(format!("Node {tag} was not found")))?;
        let node = node.tree_without_dependencies();

        // The output must be a scalar node, and `node` is a mapping node.
        // So we wrap it in a collection node.
        let wrapped = Node::new(NodeKind::Collect {
            store_in: tag.collected(),
            values: node.get_strong_ref(),
            group: PartyGroup::new(core::slice::from_ref(guilty_party)),
        });

        Ok(wrapped)
    }

    fn is_local(&self) -> bool {
        for node in self.flattened_args_only() {
            if matches!(node.kind(), NodeKind::Receive { .. }) {
                return false;
            }
        }
        true
    }

    pub(crate) fn reproducibility(&self) -> Reproducibility {
        let mut arguments = BTreeSet::<String>::new();
        let mut messages = BTreeSet::<FullName>::new();

        for node in self.flattened_args_only() {
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

        for node in self.flattened_leaves_first() {
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

/// Iterates over the node subtree in unspecified order.
///
/// Guaranteed to only emit each node once.
pub(crate) struct UnorderedIterator<SP: SessionParameters> {
    queue: Vec<Node<SP>>,
    emitted: BTreeSet<usize>,
    args_only: bool,
}

impl<SP: SessionParameters> UnorderedIterator<SP> {
    fn new(root: &Node<SP>, args_only: bool) -> Self {
        Self {
            queue: vec![root.get_strong_ref()],
            emitted: BTreeSet::new(),
            args_only,
        }
    }
}

impl<SP: SessionParameters> Iterator for UnorderedIterator<SP> {
    type Item = Node<SP>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(node) = self.queue.pop() {
            let children = if self.args_only {
                node.kind().args()
            } else {
                Box::new(node.dependencies().iter().chain(node.kind().args()))
            };
            for child_node in children {
                if !self.emitted.contains(&child_node.id()) {
                    self.queue.push(child_node.get_strong_ref());
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
    queue: Vec<Node<SP>>,
    emitted: BTreeSet<usize>,
}

impl<SP: SessionParameters> LeavesFirstIterator<SP> {
    fn new(root: &Node<SP>) -> Self {
        Self {
            queue: vec![root.get_strong_ref()],
            emitted: BTreeSet::new(),
        }
    }
}

impl<SP: SessionParameters> Iterator for LeavesFirstIterator<SP> {
    type Item = Node<SP>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.queue.pop() {
            if self.emitted.contains(&node.id()) {
                continue;
            }

            let unprocessed_children = node
                .dependencies()
                .iter()
                .chain(node.kind().args())
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
            self.queue.extend(unprocessed_children.into_iter());
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
        args: BTreeMap<String, Node<SP>>,
    },
    SerializeAndSign {
        store_in: MappingTag,
        function: SerializeAndSignFunction<SP>,
        data: Node<SP>,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        message_name: FullName,
    },
    Deserialize {
        store_in: MappingTag,
        function: DeserializeFunction<SP>,
        data: Node<SP>,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
    },
    DirectMessage {
        store_in: MappingTag,
        data: Node<SP>,
    },
    Collect {
        store_in: ScalarTag,
        values: Node<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Receive {
        store_in: MappingTag,
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
                args,
            } => Self::ComputeMapping {
                store_in: store_in.clone(),
                function: function.clone(),
                args: arg_map_to_owned(args),
            },
            Self::SerializeAndSign {
                store_in,
                function,
                data,
                message_name,
                serde_adapter,
            } => Self::SerializeAndSign {
                store_in: store_in.clone(),
                function: function.clone(),
                data: data.get_strong_ref(),
                message_name: message_name.clone(),
                serde_adapter: serde_adapter.clone(),
            },
            Self::Deserialize {
                store_in,
                function,
                data,
                serde_adapter,
            } => Self::Deserialize {
                store_in: store_in.clone(),
                function: function.clone(),
                data: data.get_strong_ref(),
                serde_adapter: serde_adapter.clone(),
            },
            Self::DirectMessage { store_in, data } => Self::DirectMessage {
                store_in: store_in.clone(),
                data: data.get_strong_ref(),
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
            Self::Receive { store_in, message_name } => Self::Receive {
                store_in: store_in.clone(),
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
