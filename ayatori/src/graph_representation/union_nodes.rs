use super::{
    any_node::AnyNode,
    specific_nodes::{
        Collect, ComputeMapping, ComputeScalar, DeserializeAndCheck, GeneralizedNode, MergeScalars, Node, NodeId,
        Receive, ScalarArgument, SendAll, SendBC, SerializeAndSignBC, SerializeAndSignDM,
    },
};
use crate::{
    entities::{AnyTagRef, ComputedScalarTag, MappingTagRef, ScalarTagRef, UnionCastError},
    traits::SessionParameters,
};

#[cfg(doc)]
use crate::protocol_author_api::Args;

macro_rules! define_node_union {
    (
        $(#[$union_meta:meta])* $union_name:ident
        $tag_ref_type:ty
        {
            $($(#[$meta:meta])* $node_type:ident),+ $(,)?
        }
    ) => {
        $(#[$union_meta])*
        #[derive_where::derive_where(Debug)]
        pub enum $union_name<SP: SessionParameters> {
            $(
                $(#[$meta])*
                $node_type(Node<$node_type<SP>>),
            )+
        }

        impl<SP: SessionParameters> $union_name<SP> {
            pub(crate) fn store_in(&self) -> $tag_ref_type {
                match self {
                    $(Self::$node_type(node) => (&node.as_ref().store_in).into(),)+
                }
            }
        }

        impl<SP: SessionParameters> GeneralizedNode for $union_name<SP> {
            fn id(&self) -> NodeId {
                match self {
                    $(Self::$node_type(node) => node.id(),)+
                }
            }

            fn get_strong_ref(&self) -> Self {
                match self {
                    $(Self::$node_type(node) => Self::$node_type(node.get_strong_ref()),)+
                }
            }
        }

        $(
            impl<SP: SessionParameters> From<Node<$node_type<SP>>> for $union_name<SP> {
                fn from(source: Node<$node_type<SP>>) -> Self {
                    Self::$node_type(source)
                }
            }

            impl<SP: SessionParameters> From<&Node<$node_type<SP>>> for $union_name<SP> {
                fn from(source: &Node<$node_type<SP>>) -> Self {
                    Self::$node_type(source.get_strong_ref())
                }
            }
        )+

        impl<SP: SessionParameters> From<$union_name<SP>> for AnyNode<SP> {
            fn from(source: $union_name<SP>) -> Self {
                match source {
                    $($union_name::$node_type(node) => AnyNode::$node_type(node),)+
                }
            }
        }

        impl<SP: SessionParameters> From<&$union_name<SP>> for AnyNode<SP> {
            fn from(source: &$union_name<SP>) -> Self {
                match source {
                    $($union_name::$node_type(node) => AnyNode::$node_type(node.get_strong_ref()),)+
                }
            }
        }

        impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for $union_name<SP> {
            type Error = UnionCastError;

            fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
                match source {
                    $(AnyNode::$node_type(node) => Ok(Self::$node_type(node)),)+
                    _ => Err(UnionCastError),
                }
            }
        }
    }
}

define_node_union!(
    /// Possible arguments to a [`ComputeScalar`] node.
    ComputeScalarArg
    ScalarTagRef<'_>
    {
        /// A result of a scalar computation.
        ///
        /// In the function, needs to be accessed via [`Args::get`].
        ComputeScalar,
        /// An input argument to the protocol.
        ///
        /// In the function, needs to be accessed via [`Args::get`].
        ScalarArgument,
        /// A result of merged scalars.
        ///
        /// In the function, needs to be accessed via [`Args::get_merged`].
        MergeScalars,
        /// A result of collecting mapping elements.
        ///
        /// In the function, needs to be accessed via [`Args::get_map`].
        Collect,
    }
);

define_node_union!(
    /// Possible arguments to a [`ComputeMapping`] node.
    ComputeMappingArg
    AnyTagRef<'_>
    {
        /// A result of a scalar computation.
        ///
        /// In the function, needs to be accessed via [`Args::get`].
        ComputeScalar,
        /// An input argument to the protocol.
        ///
        /// In the function, needs to be accessed via [`Args::get`].
        ScalarArgument,
        /// A result of merged scalars.
        ///
        /// In the function, needs to be accessed via [`Args::get_merged`].
        MergeScalars,
        /// A result of collecting mapping elements.
        ///
        /// In the function, needs to be accessed via [`Args::get_map`].
        Collect,
        /// A result of a mapping computation (for the same ID as this computation is called for).
        ///
        /// In the function, needs to be accessed via [`Args::get`].
        ComputeMapping,
        /// A result of serialization.
        ///
        /// In the function, needs to be accessed via [`Args::get`].
        SerializeAndSignBC,
        /// A result of serialization.
        ///
        /// In the function, needs to be accessed via [`Args::get`].
        SerializeAndSignDM,
        /// A result of deserialization.
        ///
        /// In the function, needs to be accessed via [`Args::get`].
        DeserializeAndCheck,
    }
);

define_node_union!(
    /// Possible arguments to a [`Collect`] node.
    CollectArg
    MappingTagRef<'_>
    {
        /// Results of a mapping computation.
        ComputeMapping,
        /// Results of a serialization.
        SerializeAndSignDM,
        /// Results of a deserialization.
        DeserializeAndCheck,
        /// Received signed (but not yet verified) values.
        Receive,
    }
);

define_node_union!(
    /// Possible arguments for message broadcasting.
    BroadcastArg
    ScalarTagRef<'_>
    {
        /// A result of a scalar computation.
        ComputeScalar,
        /// An input argument to the protocol.
        ScalarArgument,
    }
);

define_node_union!(
    /// Possible arguments for outcoming direct messages.
    DirectMessageArg
    AnyTagRef<'_>
    {
        /// A result of a scalar computation.
        ComputeScalar,
        /// An input argument to the protocol.
        ScalarArgument,
        /// A result of a mapping computation.
        ComputeMapping,
        /// A result of a deserialization.
        DeserializeAndCheck,
    }
);

define_node_union!(
    /// Possible output nodes of an [`ExecutableGraph`].
    OutputNode
    &ComputedScalarTag
    {
        /// A result of a scalar computation
        ComputeScalar,
    }
);

define_node_union!(
    /// A possible dependency for a graph node.
    Dependency
    ScalarTagRef<'_>
    {
        /// A result of a scalar computation.
        ComputeScalar,
        /// A result of collecting mapping elements.
        Collect,
        /// A result of merging two scalar values.
        MergeScalars,
        /// A result of sending a broadcast.
        SendBC,
        /// A result of sending a set of direct messages.
        SendAll,
    }
);
