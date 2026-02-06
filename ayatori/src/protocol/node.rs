use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display},
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::fmt::Debug;

use itertools::Itertools;

use super::{
    function::{ArrayFunction, ScalarFunction},
    party::PartyGroup,
    tag::Tag,
    traits::SessionParameters,
    value::SerdeAdapter,
};

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

    pub(crate) fn all_dependencies(&self) -> Box<dyn Iterator<Item = &Node<SP>> + '_> {
        self.0.all_dependencies()
    }

    fn unwrap_or_shallow_clone(self) -> TypedNode<SP> {
        Arc::try_unwrap(self.0).unwrap_or_else(|arc| arc.shallow_clone())
    }

    pub(crate) fn with_replacements(self, replacements: &BTreeMap<usize, Node<SP>>) -> Node<SP> {
        Self::new_typed(self.unwrap_or_shallow_clone().with_replacements(replacements))
    }

    pub(crate) fn shallow_with_added_prefix(self, prefix: &str) -> Self {
        Self::new_typed(self.unwrap_or_shallow_clone().with_added_prefix(prefix))
    }

    pub fn shallow_display(&self) -> String {
        format!("{}", self.0.as_ref())
    }

    pub(crate) fn flattened(&self, terminate_at: Option<&[Self]>) -> Vec<Self> {
        let mut nodes_to_process = vec![self.get_strong_ref()];
        let mut nodes_seen = BTreeSet::new();
        let mut flat_nodes = Vec::new();
        let terminate_at_ids = terminate_at
            .map(|nodes| nodes.iter().map(|node| node.id()).collect::<BTreeSet<_>>())
            .unwrap_or_default();

        while let Some(node) = nodes_to_process.pop() {
            nodes_seen.insert(node.id());
            flat_nodes.push(node.get_strong_ref());
            nodes_to_process.extend(node.all_dependencies().filter_map(|dependency| {
                let id = dependency.id();
                if nodes_seen.contains(&id) || terminate_at_ids.contains(&id) {
                    None
                } else {
                    Some(dependency.get_strong_ref())
                }
            }));
        }
        flat_nodes.reverse();
        flat_nodes
    }

    pub(crate) fn with_added_prefix(&self, prefix: &str, terminate_at: Vec<Self>) -> Self {
        let root_id = self.id();
        let mut replacement_nodes = terminate_at
            .iter()
            .map(|node| (node.id(), node.get_strong_ref()))
            .collect::<BTreeMap<_, _>>();

        for node in self.flattened(Some(&terminate_at)) {
            let old_id = node.id();
            let new_node = node
                .with_replacements(&replacement_nodes)
                .shallow_with_added_prefix(prefix);
            replacement_nodes.insert(old_id, new_node);
        }

        replacement_nodes.remove(&root_id).expect("The root node was processed")
    }
}

impl<SP: SessionParameters> Display for Node<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        for node in self.flattened(None) {
            writeln!(f, "{}", node.shallow_display())?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct TypedNode<SP: SessionParameters> {
    store_in: Tag,
    kind: NodeKind<SP>,
    dependencies: Vec<Node<SP>>,
}

impl<SP: SessionParameters> TypedNode<SP> {
    pub fn new(store_in: Tag, kind: NodeKind<SP>) -> Self {
        Self {
            store_in,
            kind,
            dependencies: Vec::new(),
        }
    }

    pub fn store_in(&self) -> &Tag {
        &self.store_in
    }

    pub fn dependencies(&self) -> &[Node<SP>] {
        &self.dependencies
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.kind.group()
    }

    pub fn kind(&self) -> &NodeKind<SP> {
        &self.kind
    }

    #[must_use]
    pub fn with_dependencies(self, dependencies: &[&Node<SP>]) -> Self {
        let mut new_node = self;
        new_node
            .dependencies
            .extend(dependencies.iter().map(|dependency| dependency.get_strong_ref()));
        new_node
    }

    #[must_use]
    pub fn with_store_in(self, name: &str) -> Self {
        let mut new_node = self;
        new_node.store_in = new_node.store_in.with_name(name);
        new_node
    }

    pub fn shallow_clone(&self) -> Self {
        Self {
            store_in: self.store_in.clone(),
            dependencies: nodes_to_owned(self.dependencies.iter()),
            kind: self.kind.shallow_clone(),
        }
    }

    pub fn all_dependencies(&self) -> Box<dyn Iterator<Item = &Node<SP>> + '_> {
        Box::new(self.dependencies.iter().chain(self.kind.all_dependencies()))
    }

    pub fn with_replacements(self, replacements: &BTreeMap<usize, Node<SP>>) -> Self {
        let mut new_node = self;
        maybe_replace_slice(&mut new_node.dependencies, replacements);
        new_node.kind.replace(replacements);
        new_node
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        let mut new_node = self;
        new_node.store_in = new_node.store_in.with_added_prefix(prefix);
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
        args: Vec<Node<SP>>,
    },
    ComputeArray {
        function: ArrayFunction<SP>,
        group: PartyGroup<SP::Verifier>,
        args: Vec<Node<SP>>,
    },
    Serialize {
        data: Node<SP>,
        group: PartyGroup<SP::Verifier>,
        adapter: SerdeAdapter<SP::WireFormat>,
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
    },
}

impl<SP: SessionParameters> Display for NodeKind<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::ComputeScalar { function, args } => {
                write!(
                    f,
                    "{function}({})",
                    args.iter().map(|arg| arg.store_in().to_string()).join(", ")
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
                    args.iter().map(|arg| arg.store_in().to_string()).join(", ")
                )
            }
            Self::DirectMessage { data, group: _group } => {
                write!(f, "direct_message({})", data.store_in())
            }
            Self::Collect { values, group: _group } => {
                write!(f, "collect({})", values.store_in())
            }
            Self::Receive { group: _group } => write!(f, "receive()"),
            Self::Serialize {
                data,
                group: _group,
                adapter: _adapter,
            } => write!(f, "serialize({})", data.store_in()),
        }
    }
}

impl<SP: SessionParameters> NodeKind<SP> {
    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        match self {
            Self::ComputeArray { group, .. }
            | Self::DirectMessage { group, .. }
            | Self::Receive { group, .. }
            | Self::Serialize { group, .. } => Some(group),
            Self::Collect { .. } | Self::ComputeScalar { .. } => None,
        }
    }

    pub fn shallow_clone(&self) -> Self {
        match self {
            Self::ComputeScalar { function, args } => Self::ComputeScalar {
                function: function.clone(),
                args: nodes_to_owned(args.iter()),
            },
            Self::ComputeArray { function, group, args } => Self::ComputeArray {
                function: function.clone(),
                group: group.clone(),
                args: nodes_to_owned(args.iter()),
            },
            Self::DirectMessage { data, group } => Self::DirectMessage {
                data: data.get_strong_ref(),
                group: group.clone(),
            },
            Self::Collect { values, group } => Self::Collect {
                values: values.get_strong_ref(),
                group: group.clone(),
            },
            Self::Receive { group } => Self::Receive { group: group.clone() },
            Self::Serialize { data, group, adapter } => Self::Serialize {
                data: data.get_strong_ref(),
                group: group.clone(),
                adapter: adapter.clone(),
            },
        }
    }

    pub fn all_dependencies(&self) -> Box<dyn Iterator<Item = &Node<SP>> + '_> {
        match self {
            Self::ComputeScalar { args, .. } | Self::ComputeArray { args, .. } => Box::new(args.iter()),
            Self::Collect { values, .. } => Box::new(core::iter::once(values)),
            Self::Serialize { data, .. } => Box::new(core::iter::once(data)),
            Self::DirectMessage { data, .. } => Box::new(core::iter::once(data)),
            Self::Receive { .. } => Box::new(core::iter::empty()),
        }
    }

    pub fn replace(&mut self, replacements: &BTreeMap<usize, Node<SP>>) {
        match self {
            Self::ComputeScalar { args, .. } => maybe_replace_slice(args, replacements),
            Self::ComputeArray { args, .. } => maybe_replace_slice(args, replacements),
            Self::Collect { values, .. } => maybe_replace(values, replacements),
            Self::Serialize { data, .. } => maybe_replace(data, replacements),
            Self::DirectMessage { data, .. } => maybe_replace(data, replacements),
            Self::Receive { .. } => {}
        }
    }
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
