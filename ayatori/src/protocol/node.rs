use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use signature::rand_core::CryptoRngCore;

use super::{
    args::Args,
    function::{
        ArrayFunction, ComputeError, ScalarFunction, WrappedArrayFunction, WrappedArrayFunctionPrivate,
        WrappedScalarFunction, WrappedScalarFunctionPrivate,
    },
    party::PartyGroup,
    tag::Tag,
    traits::SessionParameters,
    value::{Erasable, SerdeAdapter, SerializedValue, Value},
};
use crate::{error::LocalError, session::SignedValue};

// `Node` intentionally does not implement `Clone` - our clones are shallow, which may be confusing for the user.
#[derive(Debug)]
pub struct Node<SP: SessionParameters>(InnerNode<SP>);

impl<SP: SessionParameters> Node<SP> {
    pub(crate) fn into_inner(self) -> InnerNode<SP> {
        self.0
    }

    pub(crate) fn as_inner_ref(&self) -> &InnerNode<SP> {
        &self.0
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.0.group()
    }

    #[must_use]
    pub fn with_dependencies(self, dependencies: &[&Self]) -> Self {
        Self(self.0.with_dependencies(dependencies))
    }

    #[must_use]
    pub fn store_in(self, name: &str) -> Self {
        Self(self.0.with_store_in(name))
    }
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub(crate) struct InnerNode<SP: SessionParameters>(Arc<TypedNode<SP>>);

impl<SP: SessionParameters> InnerNode<SP> {
    pub fn new(typed_node: TypedNode<SP>) -> Self {
        Self(Arc::new(typed_node))
    }

    #[must_use]
    pub fn with_dependencies(self, dependencies: &[&Node<SP>]) -> Self {
        let mut typed_node = Arc::unwrap_or_clone(self.0);
        typed_node.dependencies.extend(nodes_to_owned(dependencies));
        Self::new(typed_node)
    }

    #[must_use]
    pub fn with_store_in(self, name: &str) -> Self {
        let mut typed_node = Arc::unwrap_or_clone(self.0);
        typed_node.store_in = typed_node.store_in.with_name(name);
        Self::new(typed_node)
    }

    pub fn as_ref(&self) -> &TypedNode<SP> {
        &self.0
    }

    pub fn id(&self) -> usize {
        // A little hacky. Is there a better way?
        Arc::as_ptr(&self.0) as usize
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.0.group()
    }
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub(crate) struct TypedNode<SP: SessionParameters> {
    store_in: Tag,
    kind: NodeKind<SP>,
    dependencies: Vec<InnerNode<SP>>,
}

impl<SP: SessionParameters> TypedNode<SP> {
    pub fn store_in(&self) -> &Tag {
        &self.store_in
    }

    pub fn dependencies(&self) -> &[InnerNode<SP>] {
        &self.dependencies
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.kind.group()
    }

    pub fn kind(&self) -> &NodeKind<SP> {
        &self.kind
    }
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub(crate) enum NodeKind<SP: SessionParameters> {
    ComputeScalar {
        function: ScalarFunction<SP>,
        args: Vec<InnerNode<SP>>,
    },
    ComputeArray {
        function: ArrayFunction<SP>,
        #[allow(unused)] // TODO (#9): to be used when we implement short-circuiting
        returns_nothing: bool,
        group: PartyGroup<SP::Verifier>,
        args: Vec<InnerNode<SP>>,
    },
    DirectMessage {
        data: InnerNode<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Collect {
        values: InnerNode<SP>,
        group: PartyGroup<SP::Verifier>,
    },
    Receive {
        group: PartyGroup<SP::Verifier>,
    },
}

fn nodes_to_owned<SP: SessionParameters>(nodes: &[&Node<SP>]) -> impl Iterator<Item = InnerNode<SP>> {
    nodes.iter().map(|node| node.as_inner_ref().clone())
}

impl<SP: SessionParameters> NodeKind<SP> {
    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        match self {
            Self::ComputeArray { group, .. } | Self::DirectMessage { group, .. } | Self::Receive { group, .. } => {
                Some(group)
            }
            Self::Collect { .. } | Self::ComputeScalar { .. } => None,
        }
    }
}

pub(crate) fn constant<SP: SessionParameters, Ret: Erasable>(name: &str, value: Ret) -> Node<SP> {
    let erased_value = Value::new(value);
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedScalarFunction::new_pre_erased(name, move |_args| {
                Ok(erased_value.clone())
            })),
            args: Vec::new(),
        },
    };
    Node(InnerNode::new(inner))
}

pub fn compute_scalar<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(Args<SP>) -> Result<Ret, ComputeError>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedScalarFunction::new(function)),
            args: nodes_to_owned(args).collect(),
        },
    };
    Ok(Node(InnerNode::new(inner)))
}

pub fn compute_scalar_private<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, Args<SP>) -> Result<Ret, ComputeError>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Private(WrappedScalarFunctionPrivate::new(function)),
            args: nodes_to_owned(args).collect(),
        },
    };
    Ok(Node(InnerNode::new(inner)))
}

pub fn compute_array<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, Args<SP>) -> Result<Ret, ComputeError>,
    group: &PartyGroup<SP::Verifier>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
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
    Ok(Node(InnerNode::new(inner)))
}

pub fn compute_array_private<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, &SP::Verifier, Args<SP>) -> Result<Ret, ComputeError>,
    group: &PartyGroup<SP::Verifier>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
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
    Ok(Node(InnerNode::new(inner)))
}

pub fn verify<SP: SessionParameters>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, Args<SP>) -> Result<(), ComputeError>,
    args: &[&Node<SP>],
) -> Result<Node<SP>, LocalError> {
    let groups = args.iter().filter_map(|arg| arg.group()).collect::<Vec<_>>();
    // TODO (#29): support compute-array with only scalar args (the group needs to be given explicitly)
    let group = *groups
        .first()
        .ok_or_else(|| LocalError::new("There must be at least one array argument"))?;
    if groups.iter().any(|g| g != &group) {
        return Err(LocalError::new("The group of all arguments must be the same"));
    }

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
    Ok(Node(InnerNode::new(inner)))
}

/// A wrapper to convert `dyn CryptoRngCore` to a sized `impl CryptoRngCore`,
/// since some RustCrypto libraries don't accept a `?Sized` RNG.
struct Rng<'a>(&'a mut dyn CryptoRngCore);

impl signature::rand_core::RngCore for Rng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.fill_bytes(bytes);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), signature::rand_core::Error> {
        self.0.try_fill_bytes(bytes)
    }
}

impl signature::rand_core::CryptoRng for Rng<'_> {}

fn serialize<SP: SessionParameters>(
    rng: &mut dyn CryptoRngCore,
    id: &SP::Verifier,
    value_name: String,
    args: Args<SP>,
    message: &ProtocolMessage,
) -> Result<Value, ComputeError> {
    let value = args.get_value(&value_name)?;
    let serialized_value = message.serde_adapter.serialize::<SP::WireFormat>(value)?;
    let mut typed_rng = Rng(rng);
    let signed_value = SignedValue::<SP>::new(&mut typed_rng, args.signer(), &message.name, id, serialized_value)?;
    Ok(Value::new(signed_value))
}

pub fn broadcast<SP: SessionParameters>(
    message: &ProtocolMessage,
    scalar: &Node<SP>,
    group: &PartyGroup<SP::Verifier>,
) -> Result<Node<SP>, LocalError> {
    let scalar = scalar.as_inner_ref().clone();
    let cloned_message = message.clone();
    let value_name = scalar.as_ref().store_in().name().to_string();

    if scalar.group().is_some() {
        return Err(LocalError::new(
            "`scalar` argument of `broadcast()` must be a scalar node",
        ));
    }

    let serialize_and_sign = InnerNode::new(TypedNode {
        store_in: Tag::signed(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            args: [scalar].into(),
            function: ArrayFunction::Private(WrappedArrayFunctionPrivate::new_pre_erased(
                "serialize",
                move |rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>| {
                    serialize::<SP>(rng, id, value_name.to_string(), args, &cloned_message)
                },
            )),
            returns_nothing: false,
            group: group.clone(),
        },
    });

    let send_node = Node(InnerNode::new(TypedNode {
        store_in: Tag::sent(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::DirectMessage {
            data: serialize_and_sign,
            group: group.clone(),
        },
    }));

    collect(&send_node)
}

pub fn send<SP: SessionParameters>(message: &ProtocolMessage, array: &Node<SP>) -> Result<Node<SP>, LocalError> {
    let array = array.as_inner_ref().clone();
    let cloned_message = message.clone();
    let value_name = array.as_ref().store_in().name().to_string();

    let group = array
        .as_ref()
        .group()
        .ok_or_else(|| LocalError::new("`array` argument of `send()` must be an array node"))?
        .clone();

    let serialize_and_sign = InnerNode::new(TypedNode {
        store_in: Tag::signed(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            args: [array].into(),
            function: ArrayFunction::Private(WrappedArrayFunctionPrivate::new_pre_erased(
                "serialize",
                move |rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>| {
                    serialize::<SP>(rng, id, value_name.clone(), args, &cloned_message)
                },
            )),
            returns_nothing: false,
            group: group.clone(),
        },
    });

    let send_node = Node(InnerNode::new(TypedNode {
        store_in: Tag::sent(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::DirectMessage {
            data: serialize_and_sign,
            group,
        },
    }));

    collect(&send_node)
}

fn deserialize<SP: SessionParameters>(args: Args<SP>, message: &ProtocolMessage) -> Result<Value, ComputeError> {
    let received = args.get::<SerializedValue>(&message.name)?;
    message
        .serde_adapter
        .deserialize::<SP::WireFormat>(received)
        .map_err(|_err| ComputeError::Data)
}

pub fn receive<SP: SessionParameters>(message: &ProtocolMessage, group: &PartyGroup<SP::Verifier>) -> Node<SP> {
    let received = InnerNode::new(TypedNode {
        store_in: Tag::received(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::Receive { group: group.clone() },
    });

    let cloned_message = message.clone();

    Node(InnerNode::new(TypedNode {
        store_in: Tag::deserialized(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            args: [received].into(),
            function: ArrayFunction::Public(WrappedArrayFunction::new_pre_erased(
                "deserialize",
                move |_id: &SP::Verifier, args: Args<SP>| deserialize::<SP>(args, &cloned_message),
            )),
            returns_nothing: false,
            group: group.clone(),
        },
    }))
}

pub fn collect<SP: SessionParameters>(values: &Node<SP>) -> Result<Node<SP>, LocalError> {
    let values = values.as_inner_ref().clone();
    let group = values
        .as_ref()
        .group()
        .ok_or_else(|| LocalError::new("`values` argument of `collect()` must be an array node"))?
        .clone();

    Ok(Node(InnerNode::new(TypedNode {
        store_in: Tag::collected(&values.as_ref().store_in),
        dependencies: Vec::new(),
        kind: NodeKind::Collect { values, group },
    })))
}

#[derive(Debug, Clone)]
pub struct ProtocolMessage {
    name: String,
    serde_adapter: SerdeAdapter,
}

impl ProtocolMessage {
    pub fn new<T: Clone + Erasable + Serialize + for<'de> Deserialize<'de>>(name: &str) -> Self {
        Self {
            name: name.into(),
            serde_adapter: SerdeAdapter::new::<T>(),
        }
    }
}
