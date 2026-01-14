use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use itertools::Itertools;

pub trait PartyId: 'static + Debug + Clone {}

impl<T: 'static + Debug + Clone> PartyId for T {}

#[derive(Debug, Clone)]
pub struct PartyGroup<Id: PartyId> {
    ids: Vec<Id>,
}

impl<Id: PartyId> PartyGroup<Id> {
    pub fn new(ids: &[Id]) -> Self {
        Self { ids: ids.into() }
    }

    pub fn ids(&self) -> &[Id] {
        &self.ids
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

pub struct Args<Id> {
    phantom: PhantomData<Id>,
}

impl<Id: PartyId> Args<Id> {
    pub fn get_map<T>(&self, name: &str) -> Option<BTreeMap<Id, T>> {
        todo!()
    }
}

pub(crate) struct WrappedFunction<Id: PartyId, P: Protocol<Id>> {
    function: Arc<dyn Fn(&P::SharedData, &Args<Id>) -> Box<dyn Any>>,
    name: String,
}

impl<Id: PartyId, P: Protocol<Id>> Debug for WrappedFunction<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedFunction {{ function: {} }}", self.name)
    }
}

impl<Id: PartyId, P: Protocol<Id>> Display for WrappedFunction<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<Id: PartyId, P: Protocol<Id>> Clone for WrappedFunction<Id, P> {
    fn clone(&self) -> Self {
        Self {
            function: self.function.clone(),
            name: self.name.clone(),
        }
    }
}

impl<Id: PartyId, P: Protocol<Id>> WrappedFunction<Id, P> {
    pub fn new<Ret: Any>(function: impl 'static + Fn(&P::SharedData, &Args<Id>) -> Ret) -> Self {
        let name = core::any::type_name_of_val(&function).to_string();
        let wrapped: Arc<dyn Fn(&P::SharedData, &Args<Id>) -> Box<dyn Any>> =
            Arc::new(move |shared_data: &P::SharedData, args: &Args<Id>| Box::new(function(shared_data, args)));
        Self {
            function: wrapped,
            name,
        }
    }
}

#[derive(Debug)]
pub struct Node<Id: PartyId, P: Protocol<Id>>(Arc<TypedNode<Id, P>>);

impl<Id: PartyId, P: Protocol<Id>> Node<Id, P> {
    // Creates another hard link to the same underlying node.
    // TODO: better name? Or just impl Clone?
    pub fn get_strong_ref(&self) -> Self {
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
    // TODO: should `store_in` and `dependencies` be common for all nodes?
    ComputeScalar {
        store_in: Tag, // TODO: can only be internal tag. Restrict the type?
        function: WrappedFunction<Id, P>,
        args: Vec<Node<Id, P>>,
        dependencies: Vec<Node<Id, P>>,
    },
    Send {
        store_in: Tag, // TODO: can only be internal tag. Restrict the type?
        send_as: Tag,  // can only be external
        data: Node<Id, P>,
        group: PartyGroup<Id>,
        dependencies: Vec<Node<Id, P>>,
    },
    Collect {
        store_in: Tag, // TODO: can only be internal tag. Restrict the type?
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
            Self::ComputeScalar { dependencies, .. } => &dependencies,
            Self::Send { dependencies, .. } => &dependencies,
            Self::Collect { dependencies, .. } => &dependencies,
            Self::Receive { .. } => &[],
        }
    }

    pub fn store_in(&self) -> &Tag {
        match self {
            Self::ComputeScalar { store_in, .. } => &store_in,
            Self::Send { store_in, .. } => &store_in,
            Self::Collect { store_in, .. } => &store_in,
            Self::Receive { store_in, .. } => &store_in,
        }
    }
}

pub fn compute_scalar<Id: PartyId, P: Protocol<Id>, Ret: Any>(
    name: &str,
    function: impl 'static + Fn(&P::SharedData, &Args<Id>) -> Ret,
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

pub fn broadcast<Id: PartyId, P: Protocol<Id>>(
    name: &str,
    scalar: &Node<Id, P>,
    group: &PartyGroup<Id>,
    dependencies: &[Node<Id, P>],
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
    type Output;

    fn build(my_id: &Id, shared_data: &Self::SharedData) -> Node<Id, Self>;
}
