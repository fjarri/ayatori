use super::{
    any_node::AnyNode,
    typed_nodes::{
        Collect, ComputeMapping, ComputeScalar, DeserializeAndCheck, DirectMessage, GeneralizedNode, MergeScalars,
        Node, NodeId, Receive, ScalarArgument, SerializeAndSign,
    },
};
use crate::{
    entities::{AnyTagRef, ComputedScalarTag, MappingTagRef, ScalarTagRef},
    traits::SessionParameters,
};

#[cfg(doc)]
use crate::protocol_author_api::Args;

/// An error returned when attempting to downcast from a larger union type to a smaller one (or a single type),
/// and the variant of the larger union is not present in the smalle one.
#[derive(Debug, Clone, Copy, displaydoc::Display)]
#[displaydoc("Failed to narrow down a union")]
pub struct UnionCastError;

impl core::error::Error for UnionCastError {}

/// Possible arguments to a [`ComputeScalar`] node.
#[derive_where::derive_where(Debug)]
pub enum ComputeScalarArg<SP: SessionParameters> {
    /// A result of a scalar computation.
    ///
    /// In the function, needs to be accessed via [`Args::get`].
    ComputeScalar(Node<ComputeScalar<SP>>),
    /// An input argument to the protocol.
    ///
    /// In the function, needs to be accessed via [`Args::get`].
    ScalarArgument(Node<ScalarArgument<SP>>),
    /// A result of merged scalars.
    ///
    /// In the function, needs to be accessed via [`Args::get_merged`].
    MergeScalars(Node<MergeScalars<SP>>),
    /// A result of collecting mapping elements.
    ///
    /// In the function, needs to be accessed via [`Args::get_map`].
    Collect(Node<Collect<SP>>),
}

impl<SP: SessionParameters> ComputeScalarArg<SP> {
    pub(crate) fn store_in(&self) -> ScalarTagRef<'_> {
        match self {
            Self::ComputeScalar(node) => ScalarTagRef::Computed(&node.as_ref().store_in),
            Self::ScalarArgument(node) => ScalarTagRef::Argument(&node.as_ref().store_in),
            Self::MergeScalars(node) => ScalarTagRef::Merged(&node.as_ref().store_in),
            Self::Collect(node) => ScalarTagRef::Collected(&node.as_ref().store_in),
        }
    }
}

impl<SP: SessionParameters> GeneralizedNode for ComputeScalarArg<SP> {
    fn id(&self) -> NodeId {
        match self {
            Self::ComputeScalar(node) => node.id(),
            Self::ScalarArgument(node) => node.id(),
            Self::MergeScalars(node) => node.id(),
            Self::Collect(node) => node.id(),
        }
    }

    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Self::ScalarArgument(node) => Self::ScalarArgument(node.get_strong_ref()),
            Self::MergeScalars(node) => Self::MergeScalars(node.get_strong_ref()),
            Self::Collect(node) => Self::Collect(node.get_strong_ref()),
        }
    }
}

impl<SP: SessionParameters> From<&Node<ComputeScalar<SP>>> for ComputeScalarArg<SP> {
    fn from(source: &Node<ComputeScalar<SP>>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<ScalarArgument<SP>>> for ComputeScalarArg<SP> {
    fn from(source: &Node<ScalarArgument<SP>>) -> Self {
        Self::ScalarArgument(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<MergeScalars<SP>>> for ComputeScalarArg<SP> {
    fn from(source: &Node<MergeScalars<SP>>) -> Self {
        Self::MergeScalars(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<Collect<SP>>> for ComputeScalarArg<SP> {
    fn from(source: &Node<Collect<SP>>) -> Self {
        Self::Collect(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for ComputeScalarArg<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(Self::ComputeScalar(node)),
            AnyNode::ScalarArgument(node) => Ok(Self::ScalarArgument(node)),
            AnyNode::MergeScalars(node) => Ok(Self::MergeScalars(node)),
            AnyNode::Collect(node) => Ok(Self::Collect(node)),
            _ => Err(UnionCastError),
        }
    }
}

/// Possible arguments to a [`ComputeMapping`] node.
#[derive_where::derive_where(Debug)]
pub enum ComputeMappingArg<SP: SessionParameters> {
    /// A result of a scalar computation.
    ///
    /// In the function, needs to be accessed via [`Args::get`].
    ComputeScalar(Node<ComputeScalar<SP>>),
    /// An input argument to the protocol.
    ///
    /// In the function, needs to be accessed via [`Args::get`].
    ScalarArgument(Node<ScalarArgument<SP>>),
    /// A result of merged scalars.
    ///
    /// In the function, needs to be accessed via [`Args::get_merged`].
    MergeScalars(Node<MergeScalars<SP>>),
    /// A result of collecting mapping elements.
    ///
    /// In the function, needs to be accessed via [`Args::get_map`].
    Collect(Node<Collect<SP>>),
    /// A result of a mapping computation (for the same ID as this computation is called for).
    ///
    /// In the function, needs to be accessed via [`Args::get`].
    ComputeMapping(Node<ComputeMapping<SP>>),
    /// A result of serialization.
    ///
    /// In the function, needs to be accessed via [`Args::get`].
    SerializeAndSign(Node<SerializeAndSign<SP>>),
    /// A result of deserialization.
    ///
    /// In the function, needs to be accessed via [`Args::get`].
    DeserializeAndCheck(Node<DeserializeAndCheck<SP>>),
}

impl<SP: SessionParameters> ComputeMappingArg<SP> {
    pub(crate) fn store_in(&self) -> AnyTagRef<'_> {
        match self {
            Self::ComputeScalar(node) => AnyTagRef::Scalar(ScalarTagRef::Computed(&node.as_ref().store_in)),
            Self::MergeScalars(node) => AnyTagRef::Scalar(ScalarTagRef::Merged(&node.as_ref().store_in)),
            Self::ScalarArgument(node) => AnyTagRef::Scalar(ScalarTagRef::Argument(&node.as_ref().store_in)),
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
            Self::MergeScalars(node) => node.id(),
            Self::ScalarArgument(node) => node.id(),
            Self::Collect(node) => node.id(),
            Self::ComputeMapping(node) => node.id(),
            Self::SerializeAndSign(node) => node.id(),
            Self::DeserializeAndCheck(node) => node.id(),
        }
    }

    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Self::MergeScalars(node) => Self::MergeScalars(node.get_strong_ref()),
            Self::ScalarArgument(node) => Self::ScalarArgument(node.get_strong_ref()),
            Self::Collect(node) => Self::Collect(node.get_strong_ref()),
            Self::ComputeMapping(node) => Self::ComputeMapping(node.get_strong_ref()),
            Self::SerializeAndSign(node) => Self::SerializeAndSign(node.get_strong_ref()),
            Self::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node.get_strong_ref()),
        }
    }
}

impl<SP: SessionParameters> From<&Node<ScalarArgument<SP>>> for ComputeMappingArg<SP> {
    fn from(source: &Node<ScalarArgument<SP>>) -> Self {
        Self::ScalarArgument(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<ComputeScalar<SP>>> for ComputeMappingArg<SP> {
    fn from(source: &Node<ComputeScalar<SP>>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<Collect<SP>>> for ComputeMappingArg<SP> {
    fn from(source: &Node<Collect<SP>>) -> Self {
        Self::Collect(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<ComputeMapping<SP>>> for ComputeMappingArg<SP> {
    fn from(source: &Node<ComputeMapping<SP>>) -> Self {
        Self::ComputeMapping(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<SerializeAndSign<SP>>> for ComputeMappingArg<SP> {
    fn from(source: &Node<SerializeAndSign<SP>>) -> Self {
        Self::SerializeAndSign(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<DeserializeAndCheck<SP>>> for ComputeMappingArg<SP> {
    fn from(source: &Node<DeserializeAndCheck<SP>>) -> Self {
        Self::DeserializeAndCheck(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for ComputeMappingArg<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(Self::ComputeScalar(node)),
            AnyNode::MergeScalars(node) => Ok(Self::MergeScalars(node)),
            AnyNode::ScalarArgument(node) => Ok(Self::ScalarArgument(node)),
            AnyNode::Collect(node) => Ok(Self::Collect(node)),
            AnyNode::ComputeMapping(node) => Ok(Self::ComputeMapping(node)),
            AnyNode::SerializeAndSign(node) => Ok(Self::SerializeAndSign(node)),
            AnyNode::DeserializeAndCheck(node) => Ok(Self::DeserializeAndCheck(node)),
            _ => Err(UnionCastError),
        }
    }
}

/// Possible arguments to a [`Collect`] node.
#[derive_where::derive_where(Debug)]
pub enum CollectArg<SP: SessionParameters> {
    /// Results of a mapping computation.
    ComputeMapping(Node<ComputeMapping<SP>>),
    /// Results of a serialization.
    SerializeAndSign(Node<SerializeAndSign<SP>>),
    /// Results of a deserialization.
    DeserializeAndCheck(Node<DeserializeAndCheck<SP>>),
    /// The tokens corresponding to messages successfully sent (will be `()` values).
    DirectMessage(Node<DirectMessage<SP>>),
    /// Received signed (but not yet verified) values.
    Receive(Node<Receive<SP>>),
}

impl<SP: SessionParameters> CollectArg<SP> {
    pub(crate) fn store_in(&self) -> MappingTagRef<'_> {
        match self {
            Self::ComputeMapping(node) => MappingTagRef::Computed(&node.as_ref().store_in),
            Self::SerializeAndSign(node) => MappingTagRef::LocalSigned(&node.as_ref().store_in),
            Self::DeserializeAndCheck(node) => MappingTagRef::Received(&node.as_ref().store_in),
            Self::DirectMessage(node) => MappingTagRef::Sent(&node.as_ref().store_in),
            Self::Receive(node) => MappingTagRef::RemoteSigned(&node.as_ref().store_in),
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

impl<SP: SessionParameters> From<&Node<ComputeMapping<SP>>> for CollectArg<SP> {
    fn from(source: &Node<ComputeMapping<SP>>) -> Self {
        Self::ComputeMapping(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<SerializeAndSign<SP>>> for CollectArg<SP> {
    fn from(source: &Node<SerializeAndSign<SP>>) -> Self {
        Self::SerializeAndSign(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<DeserializeAndCheck<SP>>> for CollectArg<SP> {
    fn from(source: &Node<DeserializeAndCheck<SP>>) -> Self {
        Self::DeserializeAndCheck(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<DirectMessage<SP>>> for CollectArg<SP> {
    fn from(source: &Node<DirectMessage<SP>>) -> Self {
        Self::DirectMessage(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<Receive<SP>>> for CollectArg<SP> {
    fn from(source: &Node<Receive<SP>>) -> Self {
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

/// Possible arguments for message broadcasting.
#[derive_where::derive_where(Debug)]
pub enum BroadcastArg<SP: SessionParameters> {
    /// A result of a scalar computation.
    ComputeScalar(Node<ComputeScalar<SP>>),
    /// An input argument to the protocol.
    ScalarArgument(Node<ScalarArgument<SP>>),
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

impl<SP: SessionParameters> From<&Node<ComputeScalar<SP>>> for BroadcastArg<SP> {
    fn from(source: &Node<ComputeScalar<SP>>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<ScalarArgument<SP>>> for BroadcastArg<SP> {
    fn from(source: &Node<ScalarArgument<SP>>) -> Self {
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

/// Possible arguments for outcoming direct messages.
#[derive_where::derive_where(Debug)]
pub enum DirectMessageArg<SP: SessionParameters> {
    /// A result of a scalar computation.
    ComputeScalar(Node<ComputeScalar<SP>>),
    /// An input argument to the protocol.
    ScalarArgument(Node<ScalarArgument<SP>>),
    /// A result of a mapping computation.
    ComputeMapping(Node<ComputeMapping<SP>>),
    /// A result of a deserialization.
    DeserializeAndCheck(Node<DeserializeAndCheck<SP>>),
}

impl<SP: SessionParameters> DirectMessageArg<SP> {
    pub(crate) fn store_in(&self) -> AnyTagRef<'_> {
        match self {
            Self::ComputeScalar(node) => AnyTagRef::Scalar(ScalarTagRef::Computed(&node.as_ref().store_in)),
            Self::ScalarArgument(node) => AnyTagRef::Scalar(ScalarTagRef::Argument(&node.as_ref().store_in)),
            Self::ComputeMapping(node) => AnyTagRef::Mapping(MappingTagRef::Computed(&node.as_ref().store_in)),
            Self::DeserializeAndCheck(node) => AnyTagRef::Mapping(MappingTagRef::Received(&node.as_ref().store_in)),
        }
    }
}

impl<SP: SessionParameters> GeneralizedNode for DirectMessageArg<SP> {
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

impl<SP: SessionParameters> From<&Node<ComputeScalar<SP>>> for DirectMessageArg<SP> {
    fn from(source: &Node<ComputeScalar<SP>>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<ComputeMapping<SP>>> for DirectMessageArg<SP> {
    fn from(source: &Node<ComputeMapping<SP>>) -> Self {
        Self::ComputeMapping(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<DeserializeAndCheck<SP>>> for DirectMessageArg<SP> {
    fn from(source: &Node<DeserializeAndCheck<SP>>) -> Self {
        Self::DeserializeAndCheck(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<BroadcastArg<SP>> for DirectMessageArg<SP> {
    fn from(source: BroadcastArg<SP>) -> Self {
        match source {
            BroadcastArg::ComputeScalar(node) => Self::ComputeScalar(node),
            BroadcastArg::ScalarArgument(node) => Self::ScalarArgument(node),
        }
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for DirectMessageArg<SP> {
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
    ComputeScalar(Node<ComputeScalar<SP>>),
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

impl<SP: SessionParameters> From<Node<ComputeScalar<SP>>> for OutputNode<SP> {
    fn from(source: Node<ComputeScalar<SP>>) -> Self {
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

/// A possible dependency for a graph node.
#[derive_where::derive_where(Debug)]
pub enum Dependency<SP: SessionParameters> {
    /// A result of a scalar computation.
    ComputeScalar(Node<ComputeScalar<SP>>),
    /// A result of collecting mapping elements.
    Collect(Node<Collect<SP>>),
    /// A result of merging two scalar values.
    MergeScalars(Node<MergeScalars<SP>>),
}

impl<SP: SessionParameters> Dependency<SP> {
    pub(crate) fn store_in(&self) -> ScalarTagRef<'_> {
        match self {
            Self::ComputeScalar(node) => ScalarTagRef::Computed(&node.as_ref().store_in),
            Self::Collect(node) => ScalarTagRef::Collected(&node.as_ref().store_in),
            Self::MergeScalars(node) => ScalarTagRef::Merged(&node.as_ref().store_in),
        }
    }
}

impl<SP: SessionParameters> GeneralizedNode for Dependency<SP> {
    fn id(&self) -> NodeId {
        match self {
            Self::ComputeScalar(node) => node.id(),
            Self::Collect(node) => node.id(),
            Self::MergeScalars(node) => node.id(),
        }
    }

    fn get_strong_ref(&self) -> Self {
        match self {
            Self::ComputeScalar(node) => Self::ComputeScalar(node.get_strong_ref()),
            Self::Collect(node) => Self::Collect(node.get_strong_ref()),
            Self::MergeScalars(node) => Self::MergeScalars(node.get_strong_ref()),
        }
    }
}

impl<SP: SessionParameters> From<&Node<ComputeScalar<SP>>> for Dependency<SP> {
    fn from(source: &Node<ComputeScalar<SP>>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<Collect<SP>>> for Dependency<SP> {
    fn from(source: &Node<Collect<SP>>) -> Self {
        Self::Collect(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<&Node<MergeScalars<SP>>> for Dependency<SP> {
    fn from(source: &Node<MergeScalars<SP>>) -> Self {
        Self::MergeScalars(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Dependency<SP> {
    type Error = UnionCastError;

    fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
        match source {
            AnyNode::ComputeScalar(node) => Ok(Self::ComputeScalar(node)),
            AnyNode::Collect(node) => Ok(Self::Collect(node)),
            AnyNode::MergeScalars(node) => Ok(Self::MergeScalars(node)),
            _ => Err(UnionCastError),
        }
    }
}
