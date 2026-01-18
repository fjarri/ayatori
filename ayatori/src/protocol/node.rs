use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::{self, Debug, Display};

use itertools::Itertools;
use rand_core::CryptoRng;

use super::wrappers::{WrappedArrayFunction, WrappedFunction, WrappedFunctionPrivate};

pub trait PartyId: 'static + Debug + Clone + PartialEq + Eq + PartialOrd + Ord + Send + Sync {}

impl<T: 'static + Debug + Clone + PartialEq + Eq + PartialOrd + Ord + Send + Sync> PartyId for T {}

#[derive(Debug, Clone)]
pub struct PartyGroup<Id: PartyId> {
    ids: BTreeSet<Id>,
}

impl<Id: PartyId> PartyGroup<Id> {
    pub fn new(ids: &[Id]) -> Self {
        Self {
            ids: ids.iter().cloned().collect(),
        }
    }

    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.ids.iter()
    }

    pub fn has_quorum(&self, ids: &BTreeSet<Id>) -> bool {
        &self.ids == ids
    }
}

impl<Id: PartyId> Display for PartyGroup<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let ids = self.ids.iter().map(|id| format!("{:?}", id)).join(", ");
        write!(f, "{{{ids}}}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TagKind {
    Internal,
    External,
    Sent,
    AllSent,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tag {
    name: String,
    kind: TagKind,
}

impl Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self.kind {
            TagKind::Internal => write!(f, "{}", self.name),
            TagKind::External => write!(f, "external({})", self.name),
            TagKind::Sent => write!(f, "sent({})", self.name),
            TagKind::AllSent => write!(f, "all-sent({})", self.name),
        }
    }
}

#[derive(Clone)]
pub struct Value(Arc<dyn Any + Send + Sync>);

impl Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "<value>")
    }
}

impl Value {
    pub(crate) fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self(Arc::new(value))
    }

    pub(crate) fn downcast<T: Clone + Any + Send + Sync>(&self) -> T {
        Arc::unwrap_or_clone(self.0.clone().downcast::<T>().unwrap())
    }
}

pub struct Args {
    values: BTreeMap<String, Value>,
}

impl Args {
    pub(crate) fn new(values: BTreeMap<Tag, Value>) -> Self {
        // TODO (#11): make sure there are no name clashes
        Self {
            values: values.into_iter().map(|(tag, value)| (tag.name, value)).collect(),
        }
    }

    pub fn get<T: Clone + Any + Send + Sync>(&self, name: &str) -> T {
        let tag = Tag {
            name: name.to_string(),
            kind: TagKind::Internal,
        };
        self.values.get(&tag.name).unwrap().downcast::<T>()
    }

    pub fn get_map<Id: PartyId, T: Clone + Any + Send + Sync>(&self, name: &str) -> BTreeMap<Id, T> {
        let value_map = self.get::<BTreeMap<Id, Value>>(name);
        value_map
            .into_iter()
            .map(|(id, value)| (id, value.downcast::<T>()))
            .collect()
    }
}

#[derive(Debug)]
pub struct Node<Id: PartyId, P: Protocol<Id>>(Arc<TypedNode<Id, P>>);

impl<Id: PartyId, P: Protocol<Id>> Node<Id, P> {
    // Creates another hard link to the same underlying node.
    pub(crate) fn get_strong_ref(&self) -> Self {
        Self(self.0.clone())
    }

    pub(crate) fn id(&self) -> usize {
        // A little hacky. Is there a better way?
        Arc::as_ptr(&self.0) as usize
    }

    pub(crate) fn as_ref(&self) -> &TypedNode<Id, P> {
        &self.0
    }
}

#[derive(Debug)]
pub(crate) enum TypedNode<Id: PartyId, P: Protocol<Id>> {
    ComputeScalar {
        store_in: Tag,
        function: WrappedFunction<Id, P>,
        args: Vec<Node<Id, P>>,
        dependencies: Vec<Node<Id, P>>,
    },
    ComputeScalarPrivate {
        store_in: Tag,
        function: WrappedFunctionPrivate<Id, P>,
        args: Vec<Node<Id, P>>,
        dependencies: Vec<Node<Id, P>>,
    },
    ComputeArray {
        store_in: Tag,
        function: WrappedArrayFunction<Id, P>,
        #[allow(unused)] // TODO (#9): to be used when we implement short-circuiting
        returns_nothing: bool,
        group: PartyGroup<Id>,
        args: Vec<Node<Id, P>>,
        dependencies: Vec<Node<Id, P>>,
    },
    Send {
        store_in: Tag,
        send_as: Tag,
        data: Node<Id, P>,
        group: PartyGroup<Id>,
        dependencies: Vec<Node<Id, P>>,
    },
    Collect {
        store_in: Tag,
        values: Node<Id, P>,
        dependencies: Vec<Node<Id, P>>,
    },
    Receive {
        store_in: Tag,
        group: PartyGroup<Id>,
    },
}

impl<Id: PartyId, P: Protocol<Id>> TypedNode<Id, P> {
    pub fn dependencies(&self) -> &[Node<Id, P>] {
        match self {
            Self::ComputeScalar { dependencies, .. } => dependencies,
            Self::ComputeScalarPrivate { dependencies, .. } => dependencies,
            Self::ComputeArray { dependencies, .. } => dependencies,
            Self::Send { dependencies, .. } => dependencies,
            Self::Collect { dependencies, .. } => dependencies,
            Self::Receive { .. } => &[],
        }
    }

    pub fn store_in(&self) -> &Tag {
        match self {
            Self::ComputeScalar { store_in, .. } => store_in,
            Self::ComputeScalarPrivate { store_in, .. } => store_in,
            Self::ComputeArray { store_in, .. } => store_in,
            Self::Send { store_in, .. } => store_in,
            Self::Collect { store_in, .. } => store_in,
            Self::Receive { store_in, .. } => store_in,
        }
    }

    pub fn group(&self) -> Option<&PartyGroup<Id>> {
        match self {
            Self::ComputeScalar { .. } => None,
            Self::ComputeScalarPrivate { .. } => None,
            Self::ComputeArray { group, .. } => Some(group),
            Self::Send { group, .. } => Some(group),
            Self::Collect { .. } => None,
            Self::Receive { group, .. } => Some(group),
        }
    }
}

pub fn compute_scalar<Id: PartyId, P: Protocol<Id>, Ret: Any + Send + Sync>(
    name: &str,
    function: impl 'static + Fn(&P::SharedData, Args) -> Ret,
    args: &[&Node<Id, P>],
    dependencies: &[&Node<Id, P>],
) -> Node<Id, P> {
    let inner = TypedNode::ComputeScalar {
        store_in: Tag {
            name: name.into(),
            kind: TagKind::Internal,
        },
        function: WrappedFunction::new(function),
        args: args.iter().map(|arg| arg.get_strong_ref()).collect(),
        dependencies: dependencies.iter().map(|dep| dep.get_strong_ref()).collect(),
    };
    Node(Arc::new(inner))
}

pub fn compute_scalar_private<Id: PartyId, P: Protocol<Id>, Ret: Any + Send + Sync>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRng, &P::SharedData, Args) -> Ret,
    args: &[&Node<Id, P>],
    dependencies: &[&Node<Id, P>],
) -> Node<Id, P> {
    let inner = TypedNode::ComputeScalarPrivate {
        store_in: Tag {
            name: name.into(),
            kind: TagKind::Internal,
        },
        function: WrappedFunctionPrivate::new(function),
        args: args.iter().map(|arg| arg.get_strong_ref()).collect(),
        dependencies: dependencies.iter().map(|dep| dep.get_strong_ref()).collect(),
    };
    Node(Arc::new(inner))
}

pub fn verify<Id: PartyId, P: Protocol<Id>>(
    name: &str,
    function: impl 'static + Fn(&Id, &P::SharedData, Args),
    args: &[&Node<Id, P>],
    dependencies: &[&Node<Id, P>],
) -> Node<Id, P> {
    let groups = args.iter().filter_map(|arg| arg.as_ref().group()).collect::<Vec<_>>();
    // TODO (#29): support compute-array with only scalar args (the group needs to be given explicitly)
    let group = groups[0];
    // TODO (#5): check that all groups are the same

    let inner = TypedNode::ComputeArray {
        store_in: Tag {
            name: name.into(),
            kind: TagKind::Internal,
        },
        function: WrappedArrayFunction::new(function),
        returns_nothing: true,
        group: group.clone(),
        args: args.iter().map(|arg| arg.get_strong_ref()).collect(),
        dependencies: dependencies.iter().map(|dep| dep.get_strong_ref()).collect(),
    };
    Node(Arc::new(inner))
}

pub fn broadcast<Id: PartyId, P: Protocol<Id>>(
    name: &str,
    scalar: &Node<Id, P>,
    group: &PartyGroup<Id>,
    dependencies: &[&Node<Id, P>],
) -> Node<Id, P> {
    let sent = Tag {
        name: name.into(),
        kind: TagKind::Sent,
    };
    let send_as = Tag {
        name: name.into(),
        kind: TagKind::External,
    };
    let sent_all = Tag {
        name: name.into(),
        kind: TagKind::AllSent,
    };
    let send_node = Node(Arc::new(TypedNode::Send {
        store_in: sent,
        send_as,
        data: scalar.get_strong_ref(),
        group: group.clone(),
        dependencies: dependencies.iter().map(|dep| dep.get_strong_ref()).collect(),
    }));
    Node(Arc::new(TypedNode::Collect {
        store_in: sent_all,
        values: send_node.get_strong_ref(),
        dependencies: Vec::new(),
    }))
}

pub fn receive<Id: PartyId, P: Protocol<Id>>(name: &str, group: &PartyGroup<Id>) -> Node<Id, P> {
    Node(Arc::new(TypedNode::Receive {
        store_in: Tag {
            name: name.into(),
            kind: TagKind::External,
        },
        group: group.clone(),
    }))
}

pub fn collect<Id: PartyId, P: Protocol<Id>>(
    name: &str,
    values: &Node<Id, P>,
    dependencies: &[&Node<Id, P>],
) -> Node<Id, P> {
    Node(Arc::new(TypedNode::Collect {
        store_in: Tag {
            name: name.into(),
            kind: TagKind::Internal,
        },
        values: values.get_strong_ref(),
        dependencies: dependencies
            .iter()
            .map(|dependency| dependency.get_strong_ref())
            .collect(),
    }))
}

pub trait Protocol<Id: PartyId>: Sized + Debug {
    type SharedData;
    type Output: 'static + Clone + Any + Send + Sync;

    fn build(my_id: &Id, shared_data: &Self::SharedData) -> Node<Id, Self>;
}
