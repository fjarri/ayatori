use super::{
    any_node::AnyNode,
    typed_nodes::{
        CollectNode, ComputeMappingNode, ComputeScalarNode, DeserializeAndCheckNode, DirectMessageNode,
        GeneralizedNode, NodeId, ReceiveNode, ScalarArgumentNode, SerializeAndSignNode, SpecificNode,
    },
};
use crate::{
    entities::{AnyTagRef, ComputedScalarTag, MappingTag, MappingTagRef, ScalarTagRef},
    traits::SessionParameters,
};

#[derive(Debug, Clone, Copy)]
pub struct UnionCastError;

#[derive_where::derive_where(Debug)]
pub enum ComputeScalarArg<SP: SessionParameters> {
    ComputeScalar(ComputeScalarNode<SP>),
    ScalarArgument(ScalarArgumentNode),
    Collect(CollectNode<SP>),
}

impl<SP: SessionParameters> ComputeScalarArg<SP> {
    pub(crate) fn store_in(&self) -> ScalarTagRef<'_> {
        match self {
            Self::ComputeScalar(node) => ScalarTagRef::Computed(&node.as_ref().store_in),
            Self::ScalarArgument(node) => ScalarTagRef::Argument(&node.as_ref().store_in),
            Self::Collect(node) => ScalarTagRef::Collected(&node.as_ref().store_in),
        }
    }
}

impl<SP: SessionParameters> GeneralizedNode for ComputeScalarArg<SP> {
    fn id(&self) -> NodeId {
        match self {
            Self::ComputeScalar(node) => node.id(),
            Self::ScalarArgument(node) => node.id(),
            Self::Collect(node) => node.id(),
        }
    }

    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Self::ScalarArgument(node) => Self::ScalarArgument(node.get_strong_ref()),
            Self::Collect(node) => Self::Collect(node.get_strong_ref()),
        }
    }
}

impl<SP: SessionParameters> From<&ComputeScalarNode<SP>> for ComputeScalarArg<SP> {
    fn from(source: &ComputeScalarNode<SP>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&ScalarArgumentNode> for ComputeScalarArg<SP> {
    fn from(source: &ScalarArgumentNode) -> Self {
        Self::ScalarArgument(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&CollectNode<SP>> for ComputeScalarArg<SP> {
    fn from(source: &CollectNode<SP>) -> Self {
        Self::Collect(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for ComputeScalarArg<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(Self::ComputeScalar(node)),
            AnyNode::ScalarArgument(node) => Ok(Self::ScalarArgument(node)),
            AnyNode::Collect(node) => Ok(Self::Collect(node)),
            _ => Err(UnionCastError),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub enum ComputeMappingArg<SP: SessionParameters> {
    ComputeScalar(ComputeScalarNode<SP>),
    Collect(CollectNode<SP>),
    ComputeMapping(ComputeMappingNode<SP>),
    SerializeAndSign(SerializeAndSignNode<SP>),
    DeserializeAndCheck(DeserializeAndCheckNode<SP>),
}

impl<SP: SessionParameters> ComputeMappingArg<SP> {
    pub(crate) fn store_in(&self) -> AnyTagRef<'_> {
        match self {
            Self::ComputeScalar(node) => AnyTagRef::Scalar(ScalarTagRef::Computed(&node.as_ref().store_in)),
            Self::Collect(node) => AnyTagRef::Scalar(ScalarTagRef::Collected(&node.as_ref().store_in)),
            Self::ComputeMapping(node) => AnyTagRef::Mapping(MappingTagRef::Computed(&node.as_ref().store_in)),
            Self::SerializeAndSign(node) => AnyTagRef::Mapping(MappingTagRef::LocalSigned(&node.as_ref().store_in)),
            Self::DeserializeAndCheck(node) => AnyTagRef::Mapping(MappingTagRef::Received(&node.as_ref().store_in)),
        }
    }
}

impl<SP: SessionParameters> GeneralizedNode for ComputeMappingArg<SP> {
    fn id(&self) -> NodeId {
        match self {
            Self::ComputeScalar(node) => node.id(),
            Self::Collect(node) => node.id(),
            Self::ComputeMapping(node) => node.id(),
            Self::SerializeAndSign(node) => node.id(),
            Self::DeserializeAndCheck(node) => node.id(),
        }
    }

    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Self::Collect(node) => Self::Collect(node.get_strong_ref()),
            Self::ComputeMapping(node) => Self::ComputeMapping(node.get_strong_ref()),
            Self::SerializeAndSign(node) => Self::SerializeAndSign(node.get_strong_ref()),
            Self::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node.get_strong_ref()),
        }
    }
}

impl<SP: SessionParameters> From<&ComputeScalarNode<SP>> for ComputeMappingArg<SP> {
    fn from(source: &ComputeScalarNode<SP>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&CollectNode<SP>> for ComputeMappingArg<SP> {
    fn from(source: &CollectNode<SP>) -> Self {
        Self::Collect(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&ComputeMappingNode<SP>> for ComputeMappingArg<SP> {
    fn from(source: &ComputeMappingNode<SP>) -> Self {
        Self::ComputeMapping(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&SerializeAndSignNode<SP>> for ComputeMappingArg<SP> {
    fn from(source: &SerializeAndSignNode<SP>) -> Self {
        Self::SerializeAndSign(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&DeserializeAndCheckNode<SP>> for ComputeMappingArg<SP> {
    fn from(source: &DeserializeAndCheckNode<SP>) -> Self {
        Self::DeserializeAndCheck(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for ComputeMappingArg<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(Self::ComputeScalar(node)),
            AnyNode::Collect(node) => Ok(Self::Collect(node)),
            AnyNode::ComputeMapping(node) => Ok(Self::ComputeMapping(node)),
            AnyNode::SerializeAndSign(node) => Ok(Self::SerializeAndSign(node)),
            AnyNode::DeserializeAndCheck(node) => Ok(Self::DeserializeAndCheck(node)),
            _ => Err(UnionCastError),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub enum CollectArg<SP: SessionParameters> {
    ComputeMapping(ComputeMappingNode<SP>),
    SerializeAndSign(SerializeAndSignNode<SP>),
    DeserializeAndCheck(DeserializeAndCheckNode<SP>),
    DirectMessage(DirectMessageNode<SP>),
    Receive(ReceiveNode<SP>),
}

impl<SP: SessionParameters> CollectArg<SP> {
    // TODO: return a MappingTagRef?
    pub(crate) fn store_in(&self) -> MappingTag {
        match self {
            Self::ComputeMapping(node) => MappingTag::Computed(node.as_ref().store_in.clone()),
            Self::SerializeAndSign(node) => MappingTag::LocalSigned(node.as_ref().store_in.clone()),
            Self::DeserializeAndCheck(node) => MappingTag::Received(node.as_ref().store_in.clone()),
            Self::DirectMessage(node) => MappingTag::Sent(node.as_ref().store_in.clone()),
            Self::Receive(node) => MappingTag::RemoteSigned(node.as_ref().store_in.clone()),
        }
    }
}

impl<SP: SessionParameters> GeneralizedNode for CollectArg<SP> {
    fn id(&self) -> NodeId {
        match self {
            Self::ComputeMapping(node) => node.id(),
            Self::SerializeAndSign(node) => node.id(),
            Self::DeserializeAndCheck(node) => node.id(),
            Self::DirectMessage(node) => node.id(),
            Self::Receive(node) => node.id(),
        }
    }

    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeMapping(node) => Self::ComputeMapping(node.get_strong_ref()),
            Self::SerializeAndSign(node) => Self::SerializeAndSign(node.get_strong_ref()),
            Self::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node.get_strong_ref()),
            Self::DirectMessage(node) => Self::DirectMessage(node.get_strong_ref()),
            Self::Receive(node) => Self::Receive(node.get_strong_ref()),
        }
    }
}

impl<SP: SessionParameters> From<&ComputeMappingNode<SP>> for CollectArg<SP> {
    fn from(source: &ComputeMappingNode<SP>) -> Self {
        Self::ComputeMapping(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&SerializeAndSignNode<SP>> for CollectArg<SP> {
    fn from(source: &SerializeAndSignNode<SP>) -> Self {
        Self::SerializeAndSign(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&DeserializeAndCheckNode<SP>> for CollectArg<SP> {
    fn from(source: &DeserializeAndCheckNode<SP>) -> Self {
        Self::DeserializeAndCheck(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&DirectMessageNode<SP>> for CollectArg<SP> {
    fn from(source: &DirectMessageNode<SP>) -> Self {
        Self::DirectMessage(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&ReceiveNode<SP>> for CollectArg<SP> {
    fn from(source: &ReceiveNode<SP>) -> Self {
        Self::Receive(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for CollectArg<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeMapping(node) => Ok(Self::ComputeMapping(node)),
            AnyNode::SerializeAndSign(node) => Ok(Self::SerializeAndSign(node)),
            AnyNode::DeserializeAndCheck(node) => Ok(Self::DeserializeAndCheck(node)),
            AnyNode::DirectMessage(node) => Ok(Self::DirectMessage(node)),
            AnyNode::Receive(node) => Ok(Self::Receive(node)),
            _ => Err(UnionCastError),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub enum BroadcastArg<SP: SessionParameters> {
    ComputeScalar(ComputeScalarNode<SP>),
    ScalarArgument(ScalarArgumentNode),
}

impl<SP: SessionParameters> GeneralizedNode for BroadcastArg<SP> {
    fn id(&self) -> NodeId {
        match self {
            Self::ComputeScalar(node) => node.id(),
            Self::ScalarArgument(node) => node.id(),
        }
    }

    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Self::ScalarArgument(node) => Self::ScalarArgument(node.get_strong_ref()),
        }
    }
}

impl<SP: SessionParameters> From<&ComputeScalarNode<SP>> for BroadcastArg<SP> {
    fn from(source: &ComputeScalarNode<SP>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&ScalarArgumentNode> for BroadcastArg<SP> {
    fn from(source: &ScalarArgumentNode) -> Self {
        Self::ScalarArgument(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for BroadcastArg<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(Self::ComputeScalar(node)),
            AnyNode::ScalarArgument(node) => Ok(Self::ScalarArgument(node)),
            _ => Err(UnionCastError),
        }
    }
}

// TODO: should we have these without Scalar variant, to be used in `send()`?
// or rename this to SendArg?
#[derive_where::derive_where(Debug)]
pub enum SerializeAndSignArg<SP: SessionParameters> {
    ComputeScalar(ComputeScalarNode<SP>),
    ScalarArgument(ScalarArgumentNode),
    ComputeMapping(ComputeMappingNode<SP>),
    DeserializeAndCheck(DeserializeAndCheckNode<SP>),
}

impl<SP: SessionParameters> SerializeAndSignArg<SP> {
    pub(crate) fn store_in(&self) -> AnyTagRef<'_> {
        match self {
            Self::ComputeScalar(node) => AnyTagRef::Scalar(ScalarTagRef::Computed(&node.as_ref().store_in)),
            Self::ScalarArgument(node) => AnyTagRef::Scalar(ScalarTagRef::Argument(&node.as_ref().store_in)),
            Self::ComputeMapping(node) => AnyTagRef::Mapping(MappingTagRef::Computed(&node.as_ref().store_in)),
            Self::DeserializeAndCheck(node) => AnyTagRef::Mapping(MappingTagRef::Received(&node.as_ref().store_in)),
        }
    }
}

impl<SP: SessionParameters> GeneralizedNode for SerializeAndSignArg<SP> {
    fn id(&self) -> NodeId {
        match self {
            Self::ComputeScalar(node) => node.id(),
            Self::ScalarArgument(node) => node.id(),
            Self::ComputeMapping(node) => node.id(),
            Self::DeserializeAndCheck(node) => node.id(),
        }
    }

    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Self::ScalarArgument(node) => Self::ScalarArgument(node.get_strong_ref()),
            Self::ComputeMapping(node) => Self::ComputeMapping(node.get_strong_ref()),
            Self::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node.get_strong_ref()),
        }
    }
}

impl<SP: SessionParameters> From<&ComputeScalarNode<SP>> for SerializeAndSignArg<SP> {
    fn from(source: &ComputeScalarNode<SP>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&ComputeMappingNode<SP>> for SerializeAndSignArg<SP> {
    fn from(source: &ComputeMappingNode<SP>) -> Self {
        Self::ComputeMapping(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&DeserializeAndCheckNode<SP>> for SerializeAndSignArg<SP> {
    fn from(source: &DeserializeAndCheckNode<SP>) -> Self {
        Self::DeserializeAndCheck(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<BroadcastArg<SP>> for SerializeAndSignArg<SP> {
    fn from(source: BroadcastArg<SP>) -> Self {
        match source {
            BroadcastArg::ComputeScalar(node) => Self::ComputeScalar(node),
            BroadcastArg::ScalarArgument(node) => Self::ScalarArgument(node),
        }
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for SerializeAndSignArg<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(Self::ComputeScalar(node)),
            AnyNode::ScalarArgument(node) => Ok(Self::ScalarArgument(node)),
            AnyNode::ComputeMapping(node) => Ok(Self::ComputeMapping(node)),
            AnyNode::DeserializeAndCheck(node) => Ok(Self::DeserializeAndCheck(node)),
            _ => Err(UnionCastError),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub enum OutputNode<SP: SessionParameters> {
    ComputeScalar(ComputeScalarNode<SP>),
}

impl<SP: SessionParameters> OutputNode<SP> {
    pub(crate) fn store_in(&self) -> &ComputedScalarTag {
        match self {
            Self::ComputeScalar(node) => &node.as_ref().store_in,
        }
    }
}

impl<SP: SessionParameters> GeneralizedNode for OutputNode<SP> {
    fn id(&self) -> NodeId {
        match self {
            Self::ComputeScalar(node) => node.id(),
        }
    }

    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
        }
    }
}

impl<SP: SessionParameters> From<ComputeScalarNode<SP>> for OutputNode<SP> {
    fn from(source: ComputeScalarNode<SP>) -> Self {
        Self::ComputeScalar(source)
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for OutputNode<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(Self::ComputeScalar(node)),
            _ => Err(UnionCastError),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub enum Dependency<SP: SessionParameters> {
    ComputeScalar(ComputeScalarNode<SP>),
    Collect(CollectNode<SP>),
}

impl<SP: SessionParameters> Dependency<SP> {
    pub(crate) fn store_in(&self) -> ScalarTagRef<'_> {
        match self {
            Self::ComputeScalar(node) => ScalarTagRef::Computed(&node.as_ref().store_in),
            Self::Collect(node) => ScalarTagRef::Collected(&node.as_ref().store_in),
        }
    }
}

impl<SP: SessionParameters> GeneralizedNode for Dependency<SP> {
    fn id(&self) -> NodeId {
        match self {
            Self::ComputeScalar(node) => node.id(),
            Self::Collect(node) => node.id(),
        }
    }

    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Self::Collect(node) => Self::Collect(node.get_strong_ref()),
        }
    }
}

impl<SP: SessionParameters> From<&ComputeScalarNode<SP>> for Dependency<SP> {
    fn from(source: &ComputeScalarNode<SP>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&CollectNode<SP>> for Dependency<SP> {
    fn from(source: &CollectNode<SP>) -> Self {
        Self::Collect(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Dependency<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(Self::ComputeScalar(node)),
            AnyNode::Collect(node) => Ok(Self::Collect(node)),
            _ => Err(UnionCastError),
        }
    }
}
