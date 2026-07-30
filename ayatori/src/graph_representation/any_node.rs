use alloc::{boxed::Box, collections::BTreeMap};
use core::fmt::{self, Display};

use super::{
    typed_nodes::{
        Collect, ComputeMapping, ComputeScalar, DeserializeAndCheck, GeneralizedNode, MergeScalars, Node, NodeId,
        Receive, ScalarArgument, SendAll, SendBC, SendDM, SerializeAndSignBC, SerializeAndSignDM, SpecificNode,
    },
    unions::Dependency,
};
use crate::{
    entities::{AnyTagRef, RuntimeError, UnionCastError},
    traits::SessionParameters,
};

// Keep the canonical list of node variants here. The generated code below is intentionally
// limited to forwarding operations whose implementation is identical for every node type.
// Operations with node-specific semantics remain explicit in `impl AnyNode`.
macro_rules! define_any_node {
    ($($(#[$meta:meta])* $node_type:ident),+ $(,)?) => {
        /// A union of all possible nodes.
        #[derive_where::derive_where(Debug)]
        pub enum AnyNode<SP: SessionParameters> {
            $(
                $(#[$meta])*
                $node_type(Node<$node_type<SP>>),
            )+
        }

        impl<SP: SessionParameters> AnyNode<SP> {
            pub(crate) fn with_replacements(self, replacements: &BTreeMap<NodeId, Self>) -> Result<Self, RuntimeError> {
                Ok(match self {
                    $(Self::$node_type(node) => Self::$node_type(node.with_replacements(replacements)?),)+
                })
            }

            pub(crate) fn with_added_prefix(self, prefix: &str) -> Self {
                match self {
                    $(Self::$node_type(node) => Self::$node_type(node.with_added_prefix(prefix)),)+
                }
            }

            pub(crate) fn store_in(&self) -> AnyTagRef<'_> {
                match self {
                    $(Self::$node_type(node) => (&node.as_ref().store_in).into(),)+
                }
            }

            pub(crate) fn dependencies(&self) -> &[Dependency<SP>] {
                match self {
                    $(Self::$node_type(node) => node.as_ref().dependencies(),)+
                }
            }

            pub(crate) fn without_dependencies(self) -> Self {
                match self {
                    $(Self::$node_type(node) => Self::$node_type(node.without_dependencies()),)+
                }
            }

            pub(crate) fn all_args(&self) -> Box<dyn Iterator<Item = Self> + '_> {
                match self {
                    $(Self::$node_type(node) => Box::new(node.as_ref().all_args()),)+
                }
            }
        }

        impl<SP: SessionParameters> GeneralizedNode for AnyNode<SP> {
            fn get_strong_ref(&self) -> Self {
                match self {
                    $(Self::$node_type(node) => Self::$node_type(node.get_strong_ref()),)+
                }
            }

            fn id(&self) -> NodeId {
                match self {
                    $(Self::$node_type(node) => node.id(),)+
                }
            }
        }

        $(
            impl<SP: SessionParameters> From<Node<$node_type<SP>>> for AnyNode<SP> {
                fn from(source: Node<$node_type<SP>>) -> Self {
                    Self::$node_type(source)
                }
            }

            impl<SP: SessionParameters> From<&Node<$node_type<SP>>> for AnyNode<SP> {
                fn from(source: &Node<$node_type<SP>>) -> Self {
                    Self::$node_type(source.get_strong_ref())
                }
            }

            impl<SP: SessionParameters> TryFrom<AnyNode<SP>> for Node<$node_type<SP>> {
                type Error = UnionCastError;
                fn try_from(source: AnyNode<SP>) -> Result<Self, Self::Error> {
                    match source {
                        AnyNode::$node_type(node) => Ok(node),
                        _ => Err(UnionCastError),
                    }
                }
            }
        )+

        impl<SP: SessionParameters> Display for AnyNode<SP> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                match self {
                    $(Self::$node_type(node) =>  write!(f, "{node}"),)+
                }
            }
        }
    };
}

define_any_node! {
    /// A scalar computation.
    ComputeScalar,
    /// A collection of mapping elements.
    Collect,
    /// A mapping computation.
    ComputeMapping,
    /// A serialization of a broadcast message.
    SerializeAndSignBC,
    /// A serialization of a direct message.
    SerializeAndSignDM,
    /// A deserialization of a broadcast message.
    DeserializeAndCheck,
    /// An outgoing broadcast message.
    SendBC,
    /// An outgoing direct message.
    SendDM,
    /// A set of outgoing direct messages.
    SendAll,
    /// An expected broadcast message.
    Receive,
    /// An argument to the protocol.
    ScalarArgument,
    /// One or both scalar node results merged into one.
    MergeScalars,
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
