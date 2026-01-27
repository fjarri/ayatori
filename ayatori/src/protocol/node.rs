use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt::{self, Debug, Display};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use signature::rand_core::CryptoRngCore;

use super::{
    function::{
        ArrayFunction, ComputeError, ScalarFunction, WrappedArrayFunction, WrappedArrayFunctionPrivate,
        WrappedScalarFunction, WrappedScalarFunctionPrivate,
    },
    party::PartyGroup,
    traits::{Protocol, SessionParameters},
    value::{Erasable, SerdeAdapter, SerializedValue, Value},
};
use crate::{error::LocalError, session::SignedValue};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TagKind {
    Computed,
    Sent,
    Received,
    Deserialized,
    Signed,
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

    pub fn deserialized(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: TagKind::Deserialized,
            collected: false,
        }
    }

    pub fn signed(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: TagKind::Signed,
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
            TagKind::Deserialized => write!(f, "deserialized({})", self.name),
            TagKind::Signed => write!(f, "signed({})", self.name),
        }?;
        if self.collected {
            write!(f, ")")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Args<SP: SessionParameters> {
    signer: Arc<SP::Signer>,
    my_id: SP::Verifier,
    values: BTreeMap<String, Value>,
}

impl<SP: SessionParameters> Args<SP> {
    pub(crate) fn new(signer: &Arc<SP::Signer>, my_id: &SP::Verifier, values: BTreeMap<Tag, Value>) -> Self {
        // TODO (#11): for now checking if there are name clashes.
        // If we encounter a situation where we do need arguments with the same name but different TagKind,
        // we need to rethink this.
        let duplicates = values.keys().duplicates_by(|tag| tag.name.clone()).collect::<Vec<_>>();
        if !duplicates.is_empty() {
            panic!("Duplicate names of arguments: {duplicates:?}");
        }

        Self {
            my_id: my_id.clone(),
            signer: signer.clone(),
            values: values.into_iter().map(|(tag, value)| (tag.name, value)).collect(),
        }
    }

    pub(crate) fn signer(&self) -> &SP::Signer {
        self.signer.as_ref()
    }

    pub fn my_id(&self) -> &SP::Verifier {
        &self.my_id
    }

    pub(crate) fn get_value(&self, name: &str) -> Result<&Value, LocalError> {
        self.values
            .get(name)
            .ok_or_else(|| LocalError::new(format!("Value {name} is present in the Args")))
    }

    pub fn get<T: Erasable>(&self, name: &str) -> Result<&T, LocalError> {
        self.get_value(name)?.downcast_ref::<T>()
    }

    pub fn get_map<T: Clone + Erasable>(&self, name: &str) -> Result<BTreeMap<&SP::Verifier, &T>, LocalError> {
        let value_map = self.get::<BTreeMap<SP::Verifier, Value>>(name)?;
        value_map
            .iter()
            .map(|(id, value)| value.downcast_ref::<T>().map(|value_ref| (id, value_ref)))
            .collect()
    }
}

#[derive(Debug)]
pub struct Node<SP: SessionParameters, P: Protocol<SP>>(Arc<TypedNode<SP, P>>);

impl<SP: SessionParameters, P: Protocol<SP>> Node<SP, P> {
    pub(crate) fn new(typed_node: TypedNode<SP, P>) -> Self {
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

    pub(crate) fn as_ref(&self) -> &TypedNode<SP, P> {
        &self.0
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
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
pub(crate) struct TypedNode<SP: SessionParameters, P: Protocol<SP>> {
    store_in: Tag,
    kind: NodeKind<SP, P>,
    dependencies: Vec<Node<SP, P>>,
}

#[derive(Debug)]
pub(crate) enum NodeKind<SP: SessionParameters, P: Protocol<SP>> {
    ComputeScalar {
        function: ScalarFunction<SP, P>,
        args: Vec<Node<SP, P>>,
    },
    ComputeArray {
        function: ArrayFunction<SP, P>,
        #[allow(unused)] // TODO (#9): to be used when we implement short-circuiting
        returns_nothing: bool,
        group: PartyGroup<SP::Verifier>,
        args: Vec<Node<SP, P>>,
    },
    DirectMessage {
        data: Node<SP, P>,
        group: PartyGroup<SP::Verifier>,
    },
    Collect {
        values: Node<SP, P>,
        group: PartyGroup<SP::Verifier>,
    },
    Receive {
        group: PartyGroup<SP::Verifier>,
    },
}

impl<SP: SessionParameters, P: Protocol<SP>> Clone for TypedNode<SP, P> {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> TypedNode<SP, P> {
    pub fn store_in(&self) -> &Tag {
        &self.store_in
    }

    pub fn dependencies(&self) -> &[Node<SP, P>] {
        &self.dependencies
    }

    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        self.kind.group()
    }

    pub fn kind(&self) -> &NodeKind<SP, P> {
        &self.kind
    }
}

fn nodes_to_owned<SP: SessionParameters, P: Protocol<SP>>(nodes: &[&Node<SP, P>]) -> impl Iterator<Item = Node<SP, P>> {
    nodes.iter().map(|node| node.get_strong_ref())
}

impl<SP: SessionParameters, P: Protocol<SP>> NodeKind<SP, P> {
    pub fn group(&self) -> Option<&PartyGroup<SP::Verifier>> {
        match self {
            Self::ComputeScalar { .. } => None,
            Self::ComputeArray { group, .. } => Some(group),
            Self::DirectMessage { group, .. } => Some(group),
            Self::Collect { .. } => None,
            Self::Receive { group, .. } => Some(group),
        }
    }
}

pub fn compute_scalar<SP: SessionParameters, P: Protocol<SP>, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&P::SharedData, Args<SP>) -> Result<Ret, ComputeError>,
    args: &[&Node<SP, P>],
) -> Result<Node<SP, P>, LocalError> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedScalarFunction::new(function)),
            args: nodes_to_owned(args).collect(),
        },
    };
    Ok(Node::new(inner))
}

pub fn compute_scalar_private<SP: SessionParameters, P: Protocol<SP>, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, &P::SharedData, Args<SP>) -> Result<Ret, ComputeError>,
    args: &[&Node<SP, P>],
) -> Result<Node<SP, P>, LocalError> {
    let inner = TypedNode {
        store_in: Tag::computed(name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeScalar {
            function: ScalarFunction::Private(WrappedScalarFunctionPrivate::new(function)),
            args: nodes_to_owned(args).collect(),
        },
    };
    Ok(Node::new(inner))
}

pub fn compute_array<SP: SessionParameters, P: Protocol<SP>, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, &P::SharedData, Args<SP>) -> Result<Ret, ComputeError>,
    group: &PartyGroup<SP::Verifier>,
    args: &[&Node<SP, P>],
) -> Result<Node<SP, P>, LocalError> {
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
    Ok(Node::new(inner))
}

pub fn compute_array_private<SP: SessionParameters, P: Protocol<SP>, Ret: Erasable>(
    name: &str,
    function: impl 'static
    + Fn(&mut dyn CryptoRngCore, &SP::Verifier, &P::SharedData, Args<SP>) -> Result<Ret, ComputeError>,
    group: &PartyGroup<SP::Verifier>,
    args: &[&Node<SP, P>],
) -> Result<Node<SP, P>, LocalError> {
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
    Ok(Node::new(inner))
}

pub fn verify<SP: SessionParameters, P: Protocol<SP>>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, &P::SharedData, Args<SP>) -> Result<(), ComputeError>,
    args: &[&Node<SP, P>],
) -> Result<Node<SP, P>, LocalError> {
    let groups = args
        .iter()
        .filter_map(|arg| arg.as_ref().kind.group())
        .collect::<Vec<_>>();
    // TODO (#29): support compute-array with only scalar args (the group needs to be given explicitly)
    let group = *groups
        .first()
        .ok_or_else(|| LocalError::new("There must be at least one array argument"))?;
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
    Ok(Node::new(inner))
}

/// A wrapper to convert `dyn CryptoRngCore` to a sized `impl CryptoRngCore`,
/// since some RustCrypto libraries don't accept a `?Sized` RNG.
struct Rng<'a>(&'a mut dyn CryptoRngCore);

impl<'a> signature::rand_core::RngCore for Rng<'a> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.fill_bytes(bytes)
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), signature::rand_core::Error> {
        self.0.try_fill_bytes(bytes)
    }
}

impl<'a> signature::rand_core::CryptoRng for Rng<'a> {}

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

pub fn broadcast<SP: SessionParameters, P: Protocol<SP>>(
    message: &ProtocolMessage,
    scalar: &Node<SP, P>,
    group: &PartyGroup<SP::Verifier>,
) -> Result<Node<SP, P>, LocalError> {
    let cloned_message = message.clone();
    let value_name = scalar.as_ref().store_in().name.to_string();

    if scalar.group().is_some() {
        return Err(LocalError::new(
            "`scalar` argument of `broadcast()` must be a scalar node",
        ));
    }

    let serialize_and_sign = Node::new(TypedNode {
        store_in: Tag::signed(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            args: [scalar.get_strong_ref()].into(),
            function: ArrayFunction::Private(WrappedArrayFunctionPrivate::new_pre_erased(
                "serialize",
                move |rng: &mut dyn CryptoRngCore, id: &SP::Verifier, _shared_data: &P::SharedData, args: Args<SP>| {
                    serialize::<SP>(rng, id, value_name.clone(), args, &cloned_message)
                },
            )),
            returns_nothing: false,
            group: group.clone(),
        },
    });

    let send_node = Node::new(TypedNode {
        store_in: Tag::sent(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::DirectMessage {
            data: serialize_and_sign,
            group: group.clone(),
        },
    });

    collect(&send_node)
}

pub fn send<SP: SessionParameters, P: Protocol<SP>>(
    message: &ProtocolMessage,
    array: &Node<SP, P>,
) -> Result<Node<SP, P>, LocalError> {
    let cloned_message = message.clone();
    let value_name = array.as_ref().store_in().name.to_string();

    let group = array
        .as_ref()
        .group()
        .ok_or_else(|| LocalError::new("`array` argument of `send()` must be an array node"))?;

    let serialize_and_sign = Node::new(TypedNode {
        store_in: Tag::signed(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            args: [array.get_strong_ref()].into(),
            function: ArrayFunction::Private(WrappedArrayFunctionPrivate::new_pre_erased(
                "serialize",
                move |rng: &mut dyn CryptoRngCore, id: &SP::Verifier, _shared_data: &P::SharedData, args: Args<SP>| {
                    serialize::<SP>(rng, id, value_name.clone(), args, &cloned_message)
                },
            )),
            returns_nothing: false,
            group: group.clone(),
        },
    });

    let send_node = Node::new(TypedNode {
        store_in: Tag::sent(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::DirectMessage {
            data: serialize_and_sign,
            group: group.clone(),
        },
    });

    collect(&send_node)
}

fn deserialize<SP: SessionParameters>(args: Args<SP>, message: &ProtocolMessage) -> Result<Value, ComputeError> {
    let received = args.get::<SerializedValue>(&message.name)?;
    message
        .serde_adapter
        .deserialize::<SP::WireFormat>(received)
        .map_err(|_err| ComputeError::Data)
}

pub fn receive<SP: SessionParameters, P: Protocol<SP>>(
    message: &ProtocolMessage,
    group: &PartyGroup<SP::Verifier>,
) -> Node<SP, P> {
    let received = Node::new(TypedNode {
        store_in: Tag::received(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::Receive { group: group.clone() },
    });

    let cloned_message = message.clone();

    Node::new(TypedNode {
        store_in: Tag::deserialized(&message.name),
        dependencies: Vec::new(),
        kind: NodeKind::ComputeArray {
            args: [received].into(),
            function: ArrayFunction::Public(WrappedArrayFunction::new_pre_erased(
                "deserialize",
                move |_id: &SP::Verifier, _shared_data: &P::SharedData, args: Args<SP>| {
                    deserialize::<SP>(args, &cloned_message)
                },
            )),
            returns_nothing: false,
            group: group.clone(),
        },
    })
}

pub fn collect<SP: SessionParameters, P: Protocol<SP>>(values: &Node<SP, P>) -> Result<Node<SP, P>, LocalError> {
    let group = values
        .as_ref()
        .group()
        .ok_or_else(|| LocalError::new("`values` argument of `collect()` must be an array node"))?;

    Ok(Node::new(TypedNode {
        store_in: Tag::collected(&values.as_ref().store_in),
        dependencies: Vec::new(),
        kind: NodeKind::Collect {
            values: values.get_strong_ref(),
            group: group.clone(),
        },
    }))
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
