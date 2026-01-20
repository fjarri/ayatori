use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::{self, Debug, Display};

use itertools::Itertools;
use rand_core::CryptoRng;

use super::function::{
    ArrayFunction, ScalarFunction, WrappedArrayFunction, WrappedArrayFunctionPrivate, WrappedFunction,
    WrappedFunctionPrivate,
};
use super::party::{PartyGroup, PartyId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TagKind {
    Computed,
    Sent,
    Received,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Tag {
    name: String,
    kind: TagKind,
    collected: bool,
}

impl Tag {
    pub fn with_name(&self, name: &str) -> Self {
        Self {
            name: name.into(),
            kind: self.kind,
            collected: self.collected,
        }
    }

    pub fn computed(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: TagKind::Computed,
            collected: false,
        }
    }

    pub fn sent(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: TagKind::Sent,
            collected: false,
        }
    }

    pub fn received(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: TagKind::Received,
            collected: false,
        }
    }

    pub fn collected(&self) -> Self {
        assert!(!self.collected);
        Self {
            name: self.name.clone(),
            kind: self.kind,
            collected: true,
        }
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if self.collected {
            write!(f, "collected(")?;
        }
        match self.kind {
            TagKind::Computed => write!(f, "{}", self.name),
            TagKind::Sent => write!(f, "sent({})", self.name),
            TagKind::Received => write!(f, "received({})", self.name),
        }?;
        if self.collected {
            write!(f, ")")?;
        }
        Ok(())
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

pub struct Args<Id> {
    my_id: Id,
    values: BTreeMap<String, Value>,
}

impl<Id: PartyId> Args<Id> {
    pub(crate) fn new(my_id: &Id, values: BTreeMap<Tag, Value>) -> Self {
        // TODO (#11): for now checking if there are name clashes.
        // If we encounter a situation where we do need arguments with the same name but different TagKind,
        // we need to rethink this.
        let duplicates = values.keys().duplicates_by(|tag| tag.name.clone()).collect::<Vec<_>>();
        if !duplicates.is_empty() {
            panic!("Duplicate names of arguments: {duplicates:?}");
        }

        Self {
            my_id: my_id.clone(),
            values: values.into_iter().map(|(tag, value)| (tag.name, value)).collect(),
        }
    }

    pub fn my_id(&self) -> &Id {
        &self.my_id
    }

    pub fn get<T: Clone + Any + Send + Sync>(&self, name: &str) -> T {
        self.values.get(name).unwrap().downcast::<T>()
    }

    pub fn get_map<T: Clone + Any + Send + Sync>(&self, name: &str) -> BTreeMap<Id, T> {
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
    pub(crate) fn new(typed_node: TypedNode<Id, P>) -> Self {
        Self(Arc::new(typed_node))
    }

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

    pub fn group(&self) -> Option<&PartyGroup<Id>> {
        self.as_ref().group()
    }

    pub fn with_dependencies(self, dependencies: &[&Self]) -> Self {
        let mut typed_node = Arc::unwrap_or_clone(self.0);
        typed_node.dependencies.extend(nodes_to_owned(dependencies));
        Self::new(typed_node)
    }

    pub fn store_in(self, name: &str) -> Self {
        let mut typed_node = Arc::unwrap_or_clone(self.0);
        typed_node.store_in = typed_node.store_in.with_name(name);
        Self::new(typed_node)
    }
}

#[derive(Debug)]
pub(crate) struct TypedNode<Id: PartyId, P: Protocol<Id>> {
    store_in: Tag,
    kind: NodeKind<Id, P>,
    dependencies: Vec<Node<Id, P>>,
}

#[derive(Debug)]
pub(crate) enum NodeKind<Id: PartyId, P: Protocol<Id>> {
    ComputeScalar {
        function: ScalarFunction<Id, P>,
        args: Vec<Node<Id, P>>,
    },
    ComputeArray {
        function: ArrayFunction<Id, P>,
        #[allow(unused)] // TODO (#9): to be used when we implement short-circuiting
        returns_nothing: bool,
        group: PartyGroup<Id>,
        args: Vec<Node<Id, P>>,
    },
    Broadcast {
        send_as: String,
        data: Node<Id, P>,
        group: PartyGroup<Id>,
    },
    DirectMessage {
        send_as: String,
        data: Node<Id, P>,
        group: PartyGroup<Id>,
    },
    Collect {
        values: Node<Id, P>,
    },
    Receive {
        group: PartyGroup<Id>,
    },
}

impl<Id: PartyId, P: Protocol<Id>> Clone for TypedNode<Id, P> {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl<Id: PartyId, P: Protocol<Id>> TypedNode<Id, P> {
    pub fn store_in(&self) -> &Tag {
        &self.store_in
    }

    pub fn dependencies(&self) -> &[Node<Id, P>] {
        &self.dependencies
    }

    pub fn group(&self) -> Option<&PartyGroup<Id>> {
        self.kind.group()
    }

    pub fn kind(&self) -> &NodeKind<Id, P> {
        &self.kind
    }
}

fn nodes_to_owned<Id: PartyId, P: Protocol<Id>>(nodes: &[&Node<Id, P>]) -> impl Iterator<Item = Node<Id, P>> {
    nodes.iter().map(|node| node.get_strong_ref())
}

impl<Id: PartyId, P: Protocol<Id>> NodeKind<Id, P> {
    pub fn group(&self) -> Option<&PartyGroup<Id>> {
        match self {
            Self::ComputeScalar { .. } => None,
            Self::ComputeArray { group, .. } => Some(group),
            Self::Broadcast { group, .. } => Some(group),
            Self::DirectMessage { group, .. } => Some(group),
            Self::Collect { .. } => None,
            Self::Receive { group, .. } => Some(group),
        }
    }
}

pub fn compute_scalar<Id: PartyId, P: Protocol<Id>, Ret: Any + Send + Sync>(
    name: &str,
    function: impl 'static + Fn(&P::SharedData, Args<Id>) -> Ret,
    args: &[&Node<Id, P>],
) -> Node<Id, P> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedFunction::new(function)),
            args: nodes_to_owned(args).collect(),
        },
    };
    Node::new(inner)
}

pub fn compute_scalar_private<Id: PartyId, P: Protocol<Id>, Ret: Any + Send + Sync>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRng, &P::SharedData, Args<Id>) -> Ret,
    args: &[&Node<Id, P>],
) -> Node<Id, P> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Private(WrappedFunctionPrivate::new(function)),
            args: nodes_to_owned(args).collect(),
        },
    };
    Node::new(inner)
}

pub fn compute_array<Id: PartyId, P: Protocol<Id>, Ret: Any + Send + Sync>(
    name: &str,
    function: impl 'static + Fn(&Id, &P::SharedData, Args<Id>) -> Ret,
    group: &PartyGroup<Id>,
    args: &[&Node<Id, P>],
) -> Node<Id, P> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            returns_nothing: false,
            function: ArrayFunction::Public(WrappedArrayFunction::new(function)),
            group: group.clone(),
            args: nodes_to_owned(args).collect(),
        },
    };
    Node::new(inner)
}

pub fn compute_array_private<Id: PartyId, P: Protocol<Id>, Ret: Any + Send + Sync>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRng, &Id, &P::SharedData, Args<Id>) -> Ret,
    group: &PartyGroup<Id>,
    args: &[&Node<Id, P>],
) -> Node<Id, P> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            returns_nothing: false,
            function: ArrayFunction::Private(WrappedArrayFunctionPrivate::new(function)),
            group: group.clone(),
            args: nodes_to_owned(args).collect(),
        },
    };
    Node::new(inner)
}

pub fn verify<Id: PartyId, P: Protocol<Id>>(
    name: &str,
    function: impl 'static + Fn(&Id, &P::SharedData, Args<Id>),
    args: &[&Node<Id, P>],
) -> Node<Id, P> {
    let groups = args
        .iter()
        .filter_map(|arg| arg.as_ref().kind.group())
        .collect::<Vec<_>>();
    // TODO (#29): support compute-array with only scalar args (the group needs to be given explicitly)
    let group = groups[0];
    // TODO (#5): check that all groups are the same

    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            function: ArrayFunction::Public(WrappedArrayFunction::new(function)),
            returns_nothing: true,
            group: group.clone(),
            args: nodes_to_owned(args).collect(),
        },
    };
    Node::new(inner)
}

pub fn broadcast<Id: PartyId, P: Protocol<Id>>(
    name: &str,
    scalar: &Node<Id, P>,
    group: &PartyGroup<Id>,
) -> Node<Id, P> {
    let send_node = Node::new(TypedNode {
        store_in: Tag::sent(name),
        dependencies: Vec::new(),
        kind: NodeKind::Broadcast {
            send_as: name.into(),
            data: scalar.get_strong_ref(),
            group: group.clone(),
        },
    });
    collect(&send_node)
}

pub fn send<Id: PartyId, P: Protocol<Id>>(name: &str, array: &Node<Id, P>) -> Node<Id, P> {
    let send_node = Node::new(TypedNode {
        store_in: Tag::sent(name),
        dependencies: Vec::new(),
        kind: NodeKind::DirectMessage {
            send_as: name.into(),
            data: array.get_strong_ref(),
            group: array.as_ref().group().unwrap().clone(),
        },
    });
    collect(&send_node)
}

pub fn receive<Id: PartyId, P: Protocol<Id>>(name: &str, group: &PartyGroup<Id>) -> Node<Id, P> {
    Node::new(TypedNode {
        store_in: Tag::received(name),
        dependencies: Vec::new(),
        kind: NodeKind::Receive { group: group.clone() },
    })
}

pub fn collect<Id: PartyId, P: Protocol<Id>>(values: &Node<Id, P>) -> Node<Id, P> {
    Node::new(TypedNode {
        store_in: Tag::collected(&values.as_ref().store_in),
        dependencies: Vec::new(),
        kind: NodeKind::Collect {
            values: values.get_strong_ref(),
        },
    })
}

pub trait Protocol<Id: PartyId>: Sized + Debug {
    type SharedData;
    type Output: 'static + Clone + Any + Send + Sync;

    fn build(my_id: &Id, shared_data: &Self::SharedData) -> Node<Id, Self>;
}
