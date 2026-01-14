use super::node::*;

#[derive(Debug)]
pub enum Collectable<Id: PartyId, P: Protocol<Id>> {
    ComputeScalar(ComputeScalarNode<Id, P>),
    Send(SendNode<Id, P>),
    Receive(ReceiveNode<Id>),
}

impl<Id: PartyId, P: Protocol<Id>> Node for Collectable<Id, P> {
    fn get_strong_ref(&self) -> Self {
        match self {
            Collectable::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Collectable::Send(node) => Self::Send(node.get_strong_ref()),
            Collectable::Receive(node) => Self::Receive(node.get_strong_ref()),
        }
    }
}

#[derive(Debug)]
pub enum Dependency<Id: PartyId, P: Protocol<Id>> {
    ComputeScalar(ComputeScalarNode<Id, P>),
    Collect(CollectNode<Id, P>),
}

impl<Id: PartyId, P: Protocol<Id>> Node for Dependency<Id, P> {
    fn get_strong_ref(&self) -> Self {
        match self {
            Dependency::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Dependency::Collect(node) => Self::Collect(node.get_strong_ref()),
        }
    }
}

#[derive(Debug)]
pub enum Arg<Id: PartyId, P: Protocol<Id>> {
    ComputeScalar(ComputeScalarNode<Id, P>),
    Collect(CollectNode<Id, P>),
}

impl<Id: PartyId, P: Protocol<Id>> Node for Arg<Id, P> {
    fn get_strong_ref(&self) -> Self {
        match self {
            Arg::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Arg::Collect(node) => Self::Collect(node.get_strong_ref()),
        }
    }
}

impl<Id: PartyId, P: Protocol<Id>> From<ComputeScalarNode<Id, P>> for Arg<Id, P> {
    fn from(source: ComputeScalarNode<Id, P>) -> Self {
        Self::ComputeScalar(source)
    }
}

impl<Id: PartyId, P: Protocol<Id>> From<CollectNode<Id, P>> for Arg<Id, P> {
    fn from(source: CollectNode<Id, P>) -> Self {
        Self::Collect(source)
    }
}
