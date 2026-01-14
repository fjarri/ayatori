use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use super::union_types::*;

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

pub(crate) trait Node {
    // Creates another hard link to the same underlying node.
    // TODO: better name?
    fn get_strong_ref(&self) -> Self;
}

pub(crate) struct WrappedFunction<Id: PartyId, P: Protocol<Id>> {
    function: Box<dyn Fn(&P::SharedData, &Args<Id>) -> Box<dyn Any>>,
    name: String,
}

impl<Id: PartyId, P: Protocol<Id>> Debug for WrappedFunction<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedFunction {{ function: {} }}", self.name)
    }
}

impl<Id: PartyId, P: Protocol<Id>> WrappedFunction<Id, P> {
    pub fn new<Ret: Any>(function: impl 'static + Fn(&P::SharedData, &Args<Id>) -> Ret) -> Self {
        let name = core::any::type_name_of_val(&function).to_string();
        let wrapped: Box<dyn Fn(&P::SharedData, &Args<Id>) -> Box<dyn Any>> =
            Box::new(move |shared_data: &P::SharedData, args: &Args<Id>| {
                Box::new(function(shared_data, args))
            });
        Self {
            function: wrapped,
            name,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ComputeScalarNodeInner<Id: PartyId, P: Protocol<Id>> {
    store_in: Tag, // TODO: can only be internal tag. Restrict the type?
    function: WrappedFunction<Id, P>,
    args: Vec<Arg<Id, P>>,
    dependencies: Vec<Dependency<Id, P>>,
}

#[derive(Debug)]
pub struct ComputeScalarNode<Id: PartyId, P: Protocol<Id>>(Arc<ComputeScalarNodeInner<Id, P>>);

impl<Id: PartyId, P: Protocol<Id>> Node for ComputeScalarNode<Id, P> {
    fn get_strong_ref(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Debug)]
pub(crate) struct SendNodeInner<Id: PartyId, P: Protocol<Id>> {
    store_in: Tag, // TODO: can only be internal tag. Restrict the type?
    send_as: Tag,  // can only be external
    data: ComputeScalarNode<Id, P>,
    group: PartyGroup<Id>,
    dependencies: Vec<Dependency<Id, P>>,
}

#[derive(Debug)]
pub struct SendNode<Id: PartyId, P: Protocol<Id>>(Arc<SendNodeInner<Id, P>>);

impl<Id: PartyId, P: Protocol<Id>> Node for SendNode<Id, P> {
    fn get_strong_ref(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Debug)]
pub(crate) struct CollectNodeInner<Id: PartyId, P: Protocol<Id>> {
    store_in: Tag, // TODO: can only be internal tag. Restrict the type?
    values: Collectable<Id, P>,
    dependencies: Vec<Dependency<Id, P>>,
}

#[derive(Debug)]
pub struct CollectNode<Id: PartyId, P: Protocol<Id>>(Arc<CollectNodeInner<Id, P>>);

impl<Id: PartyId, P: Protocol<Id>> Node for CollectNode<Id, P> {
    fn get_strong_ref(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Debug)]
pub(crate) struct ReceiveNodeInner<Id: PartyId> {
    store_in: Tag,
    group: PartyGroup<Id>,
}

#[derive(Debug)]
pub struct ReceiveNode<Id: PartyId>(Arc<ReceiveNodeInner<Id>>);

impl<Id: PartyId> Node for ReceiveNode<Id> {
    fn get_strong_ref(&self) -> Self {
        Self(self.0.clone())
    }
}

pub fn compute_scalar<Id: PartyId, P: Protocol<Id>, Ret: Any>(
    name: &str,
    function: impl 'static + Fn(&P::SharedData, &Args<Id>) -> Ret,
    args: &[Arg<Id, P>],
    dependencies: &[Dependency<Id, P>],
) -> ComputeScalarNode<Id, P> {
    let inner = ComputeScalarNodeInner {
        store_in: Tag {
            name: name.into(),
            kind: TagKind::Internal,
        },
        function: WrappedFunction::new(function),
        args: args.iter().map(|arg| arg.get_strong_ref()).collect(),
        dependencies: dependencies
            .iter()
            .map(|dep| dep.get_strong_ref())
            .collect(),
    };
    ComputeScalarNode(Arc::new(inner))
}

pub fn broadcast<Id: PartyId, P: Protocol<Id>>(
    name: &str,
    scalar: &ComputeScalarNode<Id, P>,
    group: &PartyGroup<Id>,
    dependencies: &[Dependency<Id, P>],
) -> CollectNode<Id, P> {
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
    let send_node = SendNode(Arc::new(SendNodeInner {
        store_in: sent,
        send_as,
        data: scalar.get_strong_ref(),
        group: group.clone(),
        dependencies: dependencies
            .iter()
            .map(|dep| dep.get_strong_ref())
            .collect(),
    }));
    CollectNode(Arc::new(CollectNodeInner {
        store_in: sent_all,
        values: Collectable::Send(send_node),
        dependencies: Vec::new(),
    }))
}

pub fn receive<Id: PartyId>(name: &str, group: &PartyGroup<Id>) -> ReceiveNode<Id> {
    ReceiveNode(Arc::new(ReceiveNodeInner {
        store_in: Tag {
            name: name.into(),
            kind: TagKind::External,
        },
        group: group.clone(),
    }))
}

pub fn collect<Id: PartyId, P: Protocol<Id>>(
    name: &str,
    values: &Collectable<Id, P>,
    dependencies: &[Dependency<Id, P>],
) -> CollectNode<Id, P> {
    CollectNode(Arc::new(CollectNodeInner {
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

    fn build(my_id: &Id, shared_data: &Self::SharedData) -> ComputeScalarNode<Id, Self>;
}
