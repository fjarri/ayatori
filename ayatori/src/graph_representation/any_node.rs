use alloc::{boxed::Box, collections::BTreeMap};
use core::fmt::{self, Display};

use super::{
    typed_nodes::{
        Collect, ComputeMapping, ComputeScalar, DeserializeAndCheck, GeneralizedNode, MergeScalars, Node, NodeId,
        Receive, ScalarArgument, SendAll, SendBC, SendDM, SerializeAndSignBC, SerializeAndSignDM, SpecificNode,
    },
    unions::{BroadcastArg, CollectArg, ComputeMappingArg, ComputeScalarArg, Dependency, DirectMessageArg, OutputNode},
};
use crate::{
    entities::{AnyTagRef, RuntimeError, UnionCastError},
    traits::SessionParameters,
};

// Keep the canonical list of node variants here. The generated code below is intentionally
// limited to forwarding operations whose implementation is identical for every node type.
// Operations with node-specific semantics remain explicit in `impl AnyNode`.
macro_rules! define_any_node {
    ($($(#[$meta:meta])* $variant:ident($node_type:ident)),+ $(,)?) => {
        /// A union of all possible nodes.
        #[derive_where::derive_where(Debug)]
        pub enum AnyNode<SP: SessionParameters> {
            $(
                $(#[$meta])*
                $variant(Node<$node_type<SP>>),
            )+
        }

        impl<SP: SessionParameters> AnyNode<SP> {
            pub(crate) fn with_replacements(self, replacements: &BTreeMap<NodeId, Self>) -> Result<Self, RuntimeError> {
                Ok(match self {
                    $(Self::$variant(node) => Self::$variant(node.with_replacements(replacements)?),)+
                })
            }

            pub(crate) fn with_added_prefix(self, prefix: &str) -> Self {
                match self {
                    $(Self::$variant(node) => Self::$variant(node.with_added_prefix(prefix)),)+
                }
            }

            pub(crate) fn store_in(&self) -> AnyTagRef<'_> {
                match self {
                    $(Self::$variant(node) => (&node.as_ref().store_in).into(),)+
                }
            }

            pub(crate) fn dependencies(&self) -> &[Dependency<SP>] {
                match self {
                    $(Self::$variant(node) => node.as_ref().dependencies(),)+
                }
            }

            pub(crate) fn without_dependencies(self) -> Self {
                match self {
                    $(Self::$variant(node) => Self::$variant(node.without_dependencies()),)+
                }
            }

            pub(crate) fn all_args(&self) -> Box<dyn Iterator<Item = Self> + '_> {
                match self {
                    $(Self::$variant(node) => Box::new(node.as_ref().all_args()),)+
                }
            }
        }

        impl<SP: SessionParameters> GeneralizedNode for AnyNode<SP> {
            fn get_strong_ref(&self) -> Self {
                match self {
                    $(Self::$variant(node) => Self::$variant(node.get_strong_ref()),)+
                }
            }

            fn id(&self) -> NodeId {
                match self {
                    $(Self::$variant(node) => node.id(),)+
                }
            }
        }

        $(
            impl<SP: SessionParameters> From<Node<$node_type<SP>>> for AnyNode<SP> {
                fn from(source: Node<$node_type<SP>>) -> Self {
                    Self::$variant(source)
                }
            }

            impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Node<$node_type<SP>> {
                type Error = UnionCastError;
                fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
                    match source {
                        AnyNode::$variant(node) => Ok(node),
                        _ => Err(UnionCastError),
                    }
                }
            }
        )+

        impl<SP: SessionParameters> Display for AnyNode<SP> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                match self {
                    $(Self::$variant(node) =>  write!(f, "{node}"),)+
                }
            }
        }
    };
}

define_any_node! {
    /// A scalar computation.
    ComputeScalar(ComputeScalar),
    /// A collection of mapping elements.
    Collect(Collect),
    /// A mapping computation.
    ComputeMapping(ComputeMapping),
    /// A serialization of a broadcast message.
    SerializeAndSignBC(SerializeAndSignBC),
    /// A serialization of a direct message.
    SerializeAndSignDM(SerializeAndSignDM),
    /// A deserialization of a broadcast message.
    DeserializeAndCheck(DeserializeAndCheck),
    /// An outgoing broadcast message.
    SendBC(SendBC),
    /// An outgoing direct message.
    SendDM(SendDM),
    /// A set of outgoing direct messages.
    SendAll(SendAll),
    /// An expected broadcast message.
    Receive(Receive),
    /// An argument to the protocol.
    ScalarArgument(ScalarArgument),
    /// One or both scalar node results merged into one.
    MergeScalars(MergeScalars),
}

impl<SP: SessionParameters> AnyNode<SP> {
    pub(crate) fn all_args_and_dependencies(&self) -> Box<dyn Iterator<Item = Self> + '_> {
        Box::new(
            self.all_args().chain(
                self.dependencies()
                    .iter()
                    .map(GeneralizedNode::get_strong_ref)
                    .map(Self::from),
            ),
        )
    }
}

impl<SP: SessionParameters> From<&Node<ComputeScalar<SP>>> for AnyNode<SP> {
    fn from(source: &Node<ComputeScalar<SP>>) -> Self {
        Self::ComputeScalar(source.get_strong_ref())
    }
}

impl<SP: SessionParameters> From<ComputeScalarArg<SP>> for AnyNode<SP> {
    fn from(source: ComputeScalarArg<SP>) -> Self {
        match source {
            ComputeScalarArg::ComputeScalar(node) => Self::ComputeScalar(node),
            ComputeScalarArg::MergeScalars(node) => Self::MergeScalars(node),
            ComputeScalarArg::ScalarArgument(node) => Self::ScalarArgument(node),
            ComputeScalarArg::Collect(node) => Self::Collect(node),
        }
    }
}

impl<SP: SessionParameters> From<CollectArg<SP>> for AnyNode<SP> {
    fn from(source: CollectArg<SP>) -> Self {
        match source {
            CollectArg::ComputeMapping(node) => Self::ComputeMapping(node),
            CollectArg::SerializeAndSign(node) => Self::SerializeAndSignDM(node),
            CollectArg::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node),
            CollectArg::Receive(node) => Self::Receive(node),
        }
    }
}

impl<SP: SessionParameters> From<ComputeMappingArg<SP>> for AnyNode<SP> {
    fn from(source: ComputeMappingArg<SP>) -> Self {
        match source {
            ComputeMappingArg::ComputeScalar(node) => Self::ComputeScalar(node),
            ComputeMappingArg::MergeScalars(node) => Self::MergeScalars(node),
            ComputeMappingArg::ScalarArgument(node) => Self::ScalarArgument(node),
            ComputeMappingArg::Collect(node) => Self::Collect(node),
            ComputeMappingArg::ComputeMapping(node) => Self::ComputeMapping(node),
            ComputeMappingArg::SerializeAndSignBC(node) => Self::SerializeAndSignBC(node),
            ComputeMappingArg::SerializeAndSignDM(node) => Self::SerializeAndSignDM(node),
            ComputeMappingArg::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node),
        }
    }
}

impl<SP: SessionParameters> From<BroadcastArg<SP>> for AnyNode<SP> {
    fn from(source: BroadcastArg<SP>) -> Self {
        match source {
            BroadcastArg::ComputeScalar(node) => Self::ComputeScalar(node),
            BroadcastArg::ScalarArgument(node) => Self::ScalarArgument(node),
        }
    }
}

impl<SP: SessionParameters> From<DirectMessageArg<SP>> for AnyNode<SP> {
    fn from(source: DirectMessageArg<SP>) -> Self {
        match source {
            DirectMessageArg::ComputeScalar(node) => Self::ComputeScalar(node),
            DirectMessageArg::ScalarArgument(node) => Self::ScalarArgument(node),
            DirectMessageArg::ComputeMapping(node) => Self::ComputeMapping(node),
            DirectMessageArg::DeserializeAndCheck(node) => Self::DeserializeAndCheck(node),
        }
    }
}

impl<SP: SessionParameters> From<Dependency<SP>> for AnyNode<SP> {
    fn from(source: Dependency<SP>) -> Self {
        match source {
            Dependency::ComputeScalar(node) => Self::ComputeScalar(node),
            Dependency::Collect(node) => Self::Collect(node),
            Dependency::MergeScalars(node) => Self::MergeScalars(node),
            Dependency::SendBC(node) => Self::SendBC(node),
            Dependency::SendAll(node) => Self::SendAll(node),
        }
    }
}

impl<SP: SessionParameters> From<OutputNode<SP>> for AnyNode<SP> {
    fn from(source: OutputNode<SP>) -> Self {
        match source {
            OutputNode::ComputeScalar(node) => Self::ComputeScalar(node),
        }
    }
}
