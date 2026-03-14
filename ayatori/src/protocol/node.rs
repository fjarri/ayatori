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

use super::{
    args::BoundProtocolArgs,
    function::{ArrayFunction, ScalarFunction},
    party::PartyGroup,
    tag::{AnyTagRef, ArrayTag, FullName, ScalarTag},
    traits::SessionParameters,
    value::SerdeAdapter,
};
use crate::error::LocalError;

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

    #[must_use]
    pub fn with_dependencies(self, dependencies: &[&Self]) -> Self {
        Self::new_typed(self.unwrap_or_shallow_clone().with_dependencies(dependencies))
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

    pub(crate) fn store_in_and_group(&self) -> Option<(&ArrayTag, &PartyGroup<SP::Verifier>)> {
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

    fn shallow_with_added_prefix(self, prefix: &str) -> Self {
        Self::new_typed(self.unwrap_or_shallow_clone().with_added_prefix(prefix))
    }

    pub fn display_tree(&self) -> String {
        let mut s = String::new();
        for node in self.flattened() {
            writeln!(&mut s, "{node}").expect("Display impl for a Node is infallible");
        }
        s
    }

    pub(crate) fn get_reproduction_subtree(&self, tag: &ArrayTag, verifier: &SP::Verifier) -> Result<Self, LocalError> {
        for node in self.flattened() {
            if node.store_in().array() == Some(tag) {
                let node = node.tree_without_dependencies();

                // The output must be a scalar node, and `node` is an array node.
                // So we wrap it in a collection node.
                let wrapped = Node::new(NodeKind::Collect {
                    store_in: tag.collected(),
                    values: node.get_strong_ref(),
                    group: PartyGroup::new(core::slice::from_ref(verifier)),
                });

                return Ok(wrapped);
            }
        }

        Err(LocalError::new(format!("Node {tag} was not found")))
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
                NodeKind::ComputeArray { function, .. } => {
                    if !function.is_reproducible() {
                        return Reproducibility::NotAvailable;
                    }
                }
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

    /// Returns the list of nodes consisting of `self` and all its subtree
    /// sorted in such a way that for every node all its dependencies preceed it.
    ///
    /// (In other words, walks the dependency tree depth-first).
    fn flattened_inner(&self, args_only: bool) -> Vec<Self> {
        let mut nodes_to_process = vec![self.get_strong_ref()];
        let mut nodes_processed = BTreeSet::new();
        let mut flat_nodes = Vec::new();

        while let Some(node) = nodes_to_process.pop() {
            let all_dependencies = if args_only {
                node.kind().args()
            } else {
                Box::new(node.dependencies().iter().chain(node.kind().args()))
            };
            let unprocessed_dependencies = all_dependencies
                .filter_map(|dependency| {
                    let id = dependency.id();
                    if nodes_processed.contains(&id) {
                        None
                    } else {
                        Some(dependency.get_strong_ref())
                    }
                })
                .collect::<Vec<_>>();

            if unprocessed_dependencies.is_empty() {
                flat_nodes.push(node.get_strong_ref());
                nodes_processed.insert(node.id());
            } else {
                nodes_to_process.push(node.get_strong_ref());
                nodes_to_process.extend(unprocessed_dependencies.into_iter());
            }
        }

        flat_nodes
    }

    pub(crate) fn flattened(&self) -> Vec<Self> {
        self.flattened_inner(false)
    }

    pub(crate) fn flattened_args(&self) -> Vec<Self> {
        self.flattened_inner(true)
    }

    pub(crate) fn with_added_prefix(&self, prefix: &str) -> Self {
        let root_id = self.id();
        let mut replacement_nodes = BTreeMap::new();

        for node in self.flattened() {
            let old_id = node.id();
            let new_node = node
                .with_replacements(&replacement_nodes)
                .shallow_with_added_prefix(prefix);
            replacement_nodes.insert(old_id, new_node);
        }

        replacement_nodes.remove(&root_id).expect("The root node was processed")
    }

    fn without_dependencies(self) -> Self {
        Self::new_typed(self.unwrap_or_shallow_clone().without_dependencies())
    }

    fn tree_without_dependencies(&self) -> Self {
        let root_id = self.id();
        let mut replacement_nodes = BTreeMap::new();

        for node in self.flattened_args() {
            let old_id = node.id();
            let new_node = node.without_dependencies().with_replacements(&replacement_nodes);
            replacement_nodes.insert(old_id, new_node);
        }

        replacement_nodes.remove(&root_id).expect("The root node was processed")
    }

    pub(crate) fn with_substituted_arguments(&self, arguments: BoundProtocolArgs<SP>) -> Result<Self, LocalError> {
        let root_id = self.id();
        let mut replacement_nodes = BTreeMap::new();

        for node in self.flattened() {
            let old_id = node.id();

            let new_node = if let NodeKind::ScalarArgument { name, .. } = node.kind() {
                arguments.get(name)?.get_strong_ref()
            } else {
                node.with_replacements(&replacement_nodes)
            };
            replacement_nodes.insert(old_id, new_node);
        }

        Ok(replacement_nodes.remove(&root_id).expect("The root node was processed"))
    }

    #[cfg(any(test, feature = "dev"))]
    pub(crate) fn with_replaced_subnode(&self, old_subnode: &Self, new_subnode: &Self) -> Self {
        let root_id = self.id();
        let mut replacement_nodes = BTreeMap::new();

        for node in self.flattened() {
            let old_id = node.id();

            let new_node = if node.id() == old_subnode.id() {
                new_subnode.get_strong_ref()
            } else {
                node.with_replacements(&replacement_nodes)
            };
            replacement_nodes.insert(old_id, new_node);
        }

        replacement_nodes.remove(&root_id).expect("The root node was processed")
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
    ComputeArray {
        store_in: ArrayTag,
        function: ArrayFunction<SP>,
        group: PartyGroup<SP::Verifier>,
        args: BTreeMap<String, Node<SP>>,
    },
    DirectMessage {
        store_in: ArrayTag,
        data: Node<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Collect {
        store_in: ScalarTag,
        values: Node<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Receive {
        store_in: ArrayTag,
        group: PartyGroup<SP::Verifier>,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
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
            Self::ComputeArray {
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
                serde_adapter: _serde_adapter,
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
            Self::ComputeArray { store_in, .. }
            | Self::DirectMessage { store_in, .. }
            | Self::Receive { store_in, .. } => AnyTagRef::Array(store_in),
        }
    }

    fn store_in_and_group(&self) -> Option<(&ArrayTag, &PartyGroup<SP::Verifier>)> {
        match self {
            Self::ComputeArray { store_in, group, .. }
            | Self::DirectMessage { store_in, group, .. }
            | Self::Receive { store_in, group, .. } => Some((store_in, group)),
            Self::Collect { .. } | Self::ComputeScalar { .. } | Self::ScalarArgument { .. } => None,
        }
    }

    fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        match self {
            Self::ComputeArray { group, .. } | Self::DirectMessage { group, .. } | Self::Receive { group, .. } => {
                Some(group)
            }
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
            Self::ComputeArray {
                store_in,
                function,
                group,
                args,
            } => Self::ComputeArray {
                store_in: store_in.clone(),
                function: function.clone(),
                group: group.clone(),
                args: arg_map_to_owned(args),
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
                serde_adapter,
            } => Self::Receive {
                store_in: store_in.clone(),
                group: group.clone(),
                message_name: message_name.clone(),
                serde_adapter: serde_adapter.clone(),
            },
            Self::ScalarArgument { store_in, name } => Self::ScalarArgument {
                store_in: store_in.clone(),
                name: name.clone(),
            },
        }
    }

    fn args(&self) -> Box<dyn Iterator<Item = &Node<SP>> + '_> {
        match self {
            Self::ComputeScalar { args, .. } | Self::ComputeArray { args, .. } => Box::new(args.values()),
            Self::Collect { values, .. } => Box::new(core::iter::once(values)),
            Self::DirectMessage { data, .. } => Box::new(core::iter::once(data)),
            Self::Receive { .. } => Box::new(core::iter::empty()),
            Self::ScalarArgument { .. } => Box::new(core::iter::empty()),
        }
    }

    fn replace(&mut self, replacements: &BTreeMap<usize, Node<SP>>) {
        match self {
            Self::ComputeScalar { args, .. } => maybe_replace_map(args, replacements),
            Self::ComputeArray { args, .. } => maybe_replace_map(args, replacements),
            Self::Collect { values, .. } => maybe_replace(values, replacements),
            Self::DirectMessage { data, .. } => maybe_replace(data, replacements),
            Self::Receive { .. } | Self::ScalarArgument { .. } => {}
        }
    }

    fn with_added_prefix(self, prefix: &str) -> Self {
        let mut result = self;
        match &mut result {
            Self::ComputeScalar { store_in, .. } => {
                *store_in = store_in.clone().with_added_prefix(prefix);
            }
            Self::ComputeArray { store_in, .. } => {
                *store_in = store_in.clone().with_added_prefix(prefix);
            }
            Self::Collect { store_in, .. } => {
                *store_in = store_in.clone().with_added_prefix(prefix);
            }
            Self::DirectMessage { store_in, .. } => {
                *store_in = store_in.clone().with_added_prefix(prefix);
            }
            Self::ScalarArgument { store_in, .. } => {
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
