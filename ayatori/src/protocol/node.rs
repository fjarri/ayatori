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
    tag::{FullName, Tag},
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

#[derive(Debug, Clone, Copy)]
pub(crate) enum Dependencies {
    All,
    ArgumentsOnly,
}

// `Node` intentionally does not implement `Clone` - our clones are shallow, which may be confusing for the user.
#[derive(Debug)]
pub struct Node<SP: SessionParameters>(Arc<TypedNode<SP>>);

impl<SP: SessionParameters> Node<SP> {
    fn new_typed(typed_node: TypedNode<SP>) -> Self {
        Self(Arc::new(typed_node))
    }

    pub(crate) fn new(store_in: Tag, kind: NodeKind<SP>) -> Self {
        Self::new_typed(TypedNode::new(store_in, kind))
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.0.group()
    }

    #[must_use]
    pub fn with_dependencies(self, dependencies: &[&Self]) -> Self {
        Self::new_typed(self.unwrap_or_shallow_clone().with_dependencies(dependencies))
    }

    #[must_use]
    pub fn with_store_in(self, name: &str) -> Self {
        Self::new_typed(self.unwrap_or_shallow_clone().with_store_in(name))
    }

    pub(crate) fn get_strong_ref(&self) -> Self {
        Self(self.0.clone())
    }

    /// NOTE: use with care. If a node is dropped and another one is created, it may get the same ID.
    fn id(&self) -> usize {
        // A little hacky. Is there a better way?
        Arc::as_ptr(&self.0) as usize
    }

    pub(crate) fn store_in(&self) -> &Tag {
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

    fn shallow_with_added_prefix(self, prefix: &str) -> Self {
        Self::new_typed(self.unwrap_or_shallow_clone().with_added_prefix(prefix))
    }

    pub fn display_tree(&self) -> String {
        let mut s = String::new();
        for node in self.flattened(None, Dependencies::All) {
            writeln!(&mut s, "{node}").expect("Display impl for a Node is infallible");
        }
        s
    }

    pub(crate) fn get_subtree(&self, tag: &Tag) -> Result<Self, LocalError> {
        for node in self.flattened(None, Dependencies::All) {
            if node.store_in() == tag {
                return Ok(node.get_strong_ref());
            }
        }
        Err(LocalError::new(format!("Node {tag} was not found")))
    }

    pub(crate) fn reproducibility(&self) -> Reproducibility {
        // TODO: get rid of recursive calls
        match self.kind() {
            NodeKind::ComputeScalar { function, args, .. } => {
                if function.takes_rng() {
                    return Reproducibility::NotAvailable;
                }

                let mut arguments = BTreeSet::<String>::new();
                let mut messages = BTreeSet::<FullName>::new();
                for arg in args.values() {
                    match arg.reproducibility() {
                        Reproducibility::Available {
                            arguments: arg_arguments,
                            messages: arg_messages,
                        } => {
                            arguments.extend(arg_arguments);
                            messages.extend(arg_messages);
                        }
                        Reproducibility::NotAvailable => return Reproducibility::NotAvailable,
                    }
                }
                Reproducibility::Available { arguments, messages }
            }
            NodeKind::ComputeArray { function, args, .. } => {
                if function.takes_rng() {
                    return Reproducibility::NotAvailable;
                }

                let mut arguments = BTreeSet::<String>::new();
                let mut messages = BTreeSet::<FullName>::new();
                for arg in args.values() {
                    match arg.reproducibility() {
                        Reproducibility::Available {
                            arguments: arg_arguments,
                            messages: arg_messages,
                        } => {
                            arguments.extend(arg_arguments);
                            messages.extend(arg_messages);
                        }
                        Reproducibility::NotAvailable => return Reproducibility::NotAvailable,
                    }
                }
                Reproducibility::Available { arguments, messages }
            }
            NodeKind::DirectMessage { .. } => {
                // We can always reproduce the result of this, since it is an infallible `()`.
                Reproducibility::Available {
                    arguments: BTreeSet::new(),
                    messages: BTreeSet::new(),
                }
            }
            NodeKind::Collect { .. } => {
                // TODO: the collect nodes that only depend on locally created values are reproducible,
                // but that's a rare case, and it requires propagating/calculating the "locality" property.
                Reproducibility::NotAvailable
            }
            NodeKind::Receive { message_name, .. } => Reproducibility::Available {
                arguments: BTreeSet::new(),
                messages: [message_name.clone()].into(),
            },
            NodeKind::ScalarArgument { name, .. } => Reproducibility::Available {
                arguments: [name.clone()].into(),
                messages: BTreeSet::new(),
            },
        }
    }

    /// Returns the list of nodes consisting of `self` and all its subtree
    /// sorted in such a way that for every node all its dependencies preceed it.
    ///
    /// (In other words, walks the dependency tree depth-first).
    pub(crate) fn flattened(&self, terminate_at: Option<&[Self]>, dependencies: Dependencies) -> Vec<Self> {
        // TODO: the arguments `terminate_at` and `dependencies` may be unused
        let mut nodes_to_process = vec![self.get_strong_ref()];
        let mut nodes_processed = BTreeSet::new();
        let mut flat_nodes = Vec::new();
        let terminate_at_ids = terminate_at
            .map(|nodes| nodes.iter().map(|node| node.id()).collect::<BTreeSet<_>>())
            .unwrap_or_default();

        while let Some(node) = nodes_to_process.pop() {
            let all_dependencies = match dependencies {
                Dependencies::ArgumentsOnly => node.kind().args(),
                Dependencies::All => Box::new(node.dependencies().iter().chain(node.kind().args())),
            };
            let unprocessed_dependencies = all_dependencies
                .filter_map(|dependency| {
                    let id = dependency.id();
                    if nodes_processed.contains(&id) || terminate_at_ids.contains(&id) {
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

    pub(crate) fn with_added_prefix(&self, prefix: &str, terminate_at: Vec<Self>) -> Self {
        let root_id = self.id();
        let mut replacement_nodes = terminate_at
            .iter()
            .map(|node| (node.id(), node.get_strong_ref()))
            .collect::<BTreeMap<_, _>>();

        for node in self.flattened(Some(&terminate_at), Dependencies::All) {
            let old_id = node.id();
            let new_node = node
                .with_replacements(&replacement_nodes)
                .shallow_with_added_prefix(prefix);
            replacement_nodes.insert(old_id, new_node);
        }

        replacement_nodes.remove(&root_id).expect("The root node was processed")
    }

    pub(crate) fn substitute_arguments(&self, arguments: BoundProtocolArgs<SP>) -> Result<Self, LocalError> {
        let root_id = self.id();
        let mut replacement_nodes = BTreeMap::new();

        for node in self.flattened(None, Dependencies::All) {
            let old_id = node.id();

            let new_node = if let NodeKind::ScalarArgument { name } = node.kind() {
                arguments.get(name)?.get_strong_ref()
            } else {
                node.with_replacements(&replacement_nodes)
            };
            replacement_nodes.insert(old_id, new_node);
        }

        Ok(replacement_nodes.remove(&root_id).expect("The root node was processed"))
    }
}

impl<SP: SessionParameters> Display for Node<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0.as_ref())
    }
}

#[derive(Debug)]
struct TypedNode<SP: SessionParameters> {
    store_in: Tag,
    kind: NodeKind<SP>,
    dependencies: Vec<Node<SP>>,
}

impl<SP: SessionParameters> TypedNode<SP> {
    fn new(store_in: Tag, kind: NodeKind<SP>) -> Self {
        Self {
            store_in,
            kind,
            dependencies: Vec::new(),
        }
    }

    fn store_in(&self) -> &Tag {
        &self.store_in
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

    #[must_use]
    fn with_store_in(self, name: &str) -> Self {
        let mut new_node = self;
        new_node.store_in = new_node.store_in.with_name(name);
        new_node
    }

    fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
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
        if !matches!(new_node.kind, NodeKind::ScalarArgument { .. }) {
            new_node.store_in = new_node.store_in.with_added_prefix(prefix);
        }
        new_node.kind = new_node.kind.with_added_prefix(prefix);
        new_node
    }
}

impl<SP: SessionParameters> Display for TypedNode<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{} = {}", self.store_in, self.kind)?;
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
        function: ScalarFunction<SP>,
        args: BTreeMap<String, Node<SP>>,
    },
    ComputeArray {
        function: ArrayFunction<SP>,
        group: PartyGroup<SP::Verifier>,
        args: BTreeMap<String, Node<SP>>,
    },
    DirectMessage {
        data: Node<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Collect {
        values: Node<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Receive {
        group: PartyGroup<SP::Verifier>,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
    },
    ScalarArgument {
        name: String,
    },
}

impl<SP: SessionParameters> Display for NodeKind<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::ComputeScalar { function, args } => {
                write!(
                    f,
                    "{function}({})",
                    args.iter()
                        .map(|(name, arg)| format!("{}={}", name, arg.store_in()))
                        .join(", ")
                )
            }
            Self::ComputeArray {
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
            Self::DirectMessage { data, group: _group } => {
                write!(f, "direct_message({})", data.store_in())
            }
            Self::Collect { values, group: _group } => {
                write!(f, "collect({})", values.store_in())
            }
            Self::Receive {
                group: _group,
                message_name: _message_name,
                serde_adapter: _serde_adapter,
            } => write!(f, "receive()"),
            Self::ScalarArgument { name } => write!(f, "argument({name})"),
        }
    }
}

impl<SP: SessionParameters> NodeKind<SP> {
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
            Self::ComputeScalar { function, args } => Self::ComputeScalar {
                function: function.clone(),
                args: arg_map_to_owned(args),
            },
            Self::ComputeArray { function, group, args } => Self::ComputeArray {
                function: function.clone(),
                group: group.clone(),
                args: arg_map_to_owned(args),
            },
            Self::DirectMessage { data, group } => Self::DirectMessage {
                data: data.get_strong_ref(),
                group: group.clone(),
            },
            Self::Collect { values, group } => Self::Collect {
                values: values.get_strong_ref(),
                group: group.clone(),
            },
            Self::Receive {
                group,
                message_name,
                serde_adapter,
            } => Self::Receive {
                group: group.clone(),
                message_name: message_name.clone(),
                serde_adapter: serde_adapter.clone(),
            },
            Self::ScalarArgument { name } => Self::ScalarArgument { name: name.clone() },
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
        match self {
            Self::ComputeScalar { .. }
            | Self::ComputeArray { .. }
            | Self::Collect { .. }
            | Self::DirectMessage { .. }
            | Self::ScalarArgument { .. } => self,
            Self::Receive {
                group,
                message_name,
                serde_adapter,
            } => Self::Receive {
                message_name: message_name.with_added_prefix(prefix),
                group,
                serde_adapter,
            },
        }
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
