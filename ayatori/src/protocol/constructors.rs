use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use serde::{Deserialize, Serialize};
use signature::rand_core::CryptoRngCore;

use super::{
    args::{Args, ProtocolArgs},
    function::{
        ArrayFunction, ComputeError, ScalarFunction, WrappedArrayFunction, WrappedArrayFunctionPrivate,
        WrappedScalarFunction, WrappedScalarFunctionPrivate,
    },
    node::{Node, NodeKind, args_to_owned},
    party::PartyGroup,
    tag::{FullName, Tag},
    traits::{ComposableProtocol, SessionParameters},
    value::{Erasable, SerdeAdapter, SerializedValue, Value},
};
use crate::{error::LocalError, session::SignedValue};

pub(crate) fn constant<SP: SessionParameters, Ret: Erasable>(name: &str, value: Ret) -> Node<SP> {
    let erased_value = Value::new(value);
    Node::new(
        Tag::computed(name),
        NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedScalarFunction::new_pre_erased(name, move |_args| {
                Ok(erased_value.clone())
            })),
            args: BTreeMap::new(),
        },
    )
}

pub(crate) fn alias<SP: SessionParameters>(name: &str, node: &Node<SP>) -> Node<SP> {
    let arg_name = "value";
    Node::new(
        Tag::computed(name),
        NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedScalarFunction::new_pre_erased("alias", move |args| {
                args.get_value(arg_name).cloned().map_err(ComputeError::Local)
            })),
            args: [(arg_name.into(), node.get_strong_ref())].into(),
        },
    )
}

pub fn compute_scalar<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(Args<SP>) -> Result<Ret, ComputeError>,
    args: &[(&str, &Node<SP>)],
) -> Result<Node<SP>, LocalError> {
    Ok(Node::new(
        Tag::computed(name),
        NodeKind::ComputeScalar {
            function: ScalarFunction::Public(WrappedScalarFunction::new(function)),
            args: args_to_owned(args.iter().cloned())?,
        },
    ))
}

pub fn compute_scalar_private<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, Args<SP>) -> Result<Ret, ComputeError>,
    args: &[(&str, &Node<SP>)],
) -> Result<Node<SP>, LocalError> {
    Ok(Node::new(
        Tag::computed(name),
        NodeKind::ComputeScalar {
            function: ScalarFunction::Private(WrappedScalarFunctionPrivate::new(function)),
            args: args_to_owned(args.iter().cloned())?,
        },
    ))
}

pub fn compute_array<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, Args<SP>) -> Result<Ret, ComputeError>,
    group: &PartyGroup<SP::Verifier>,
    args: &[(&str, &Node<SP>)],
) -> Result<Node<SP>, LocalError> {
    Ok(Node::new(
        Tag::computed(name),
        NodeKind::ComputeArray {
            function: ArrayFunction::Public(WrappedArrayFunction::new(function)),
            group: group.clone(),
            args: args_to_owned(args.iter().cloned())?,
        },
    ))
}

pub fn compute_array_private<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, &SP::Verifier, Args<SP>) -> Result<Ret, ComputeError>,
    group: &PartyGroup<SP::Verifier>,
    args: &[(&str, &Node<SP>)],
) -> Result<Node<SP>, LocalError> {
    Ok(Node::new(
        Tag::computed(name),
        NodeKind::ComputeArray {
            function: ArrayFunction::Private(WrappedArrayFunctionPrivate::new(function)),
            group: group.clone(),
            args: args_to_owned(args.iter().cloned())?,
        },
    ))
}

pub fn verify<SP: SessionParameters>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, Args<SP>) -> Result<(), ComputeError>,
    args: &[(&str, &Node<SP>)],
) -> Result<Node<SP>, LocalError> {
    let groups = args.iter().filter_map(|(_name, arg)| arg.group()).collect::<Vec<_>>();
    // TODO (#29): support compute-array with only scalar args (the group needs to be given explicitly)
    let group = *groups
        .first()
        .ok_or_else(|| LocalError::new("There must be at least one array argument"))?;
    if groups.iter().any(|g| g != &group) {
        return Err(LocalError::new("The group of all arguments must be the same"));
    }

    Ok(Node::new(
        Tag::computed(name),
        NodeKind::ComputeArray {
            function: ArrayFunction::Public(WrappedArrayFunction::new(function)),
            group: group.clone(),
            args: args_to_owned(args.iter().cloned())?,
        },
    ))
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
    args: Args<SP>,
    arg_name: &str,
    message_name: &FullName,
    serde_adapter: &SerdeAdapter<SP::WireFormat>,
) -> Result<Value, ComputeError> {
    let value = args.get_value(arg_name)?;
    let serialized_value = serde_adapter.serialize(value)?;
    let mut typed_rng = Rng(rng);
    let signed_value = SignedValue::<SP>::new(&mut typed_rng, args.signer(), message_name, id, serialized_value)?;
    Ok(Value::new(signed_value))
}

pub(crate) fn serialize_function<SP: SessionParameters>(
    arg_name: &str,
    store_in: &Tag,
    adapter: &SerdeAdapter<SP::WireFormat>,
) -> ArrayFunction<SP> {
    let adapter = adapter.clone();
    let arg_name = arg_name.to_string();
    let message_name = store_in.full_name().clone();
    ArrayFunction::Private(WrappedArrayFunctionPrivate::new_pre_erased(
        "serialize",
        move |rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>| {
            serialize::<SP>(rng, id, args, &arg_name, &message_name, &adapter)
        },
    ))
}

pub fn broadcast<SP: SessionParameters>(
    message: &ProtocolMessage<SP>,
    scalar: &Node<SP>,
    group: &PartyGroup<SP::Verifier>,
) -> Result<Node<SP>, LocalError> {
    if scalar.group().is_some() {
        return Err(LocalError::new(
            "`scalar` argument of `broadcast()` must be a scalar node",
        ));
    }

    let serialize_and_sign = Node::new(
        Tag::signed(&message.name),
        NodeKind::Serialize {
            data: scalar.get_strong_ref(),
            group: group.clone(),
            adapter: message.serde_adapter.clone(),
        },
    );

    let send_node = Node::new(
        Tag::sent(&message.name),
        NodeKind::DirectMessage {
            data: serialize_and_sign,
            group: group.clone(),
        },
    );

    collect(&send_node)
}

pub fn send<SP: SessionParameters>(message: &ProtocolMessage<SP>, array: &Node<SP>) -> Result<Node<SP>, LocalError> {
    let group = array
        .group()
        .ok_or_else(|| LocalError::new("`array` argument of `send()` must be an array node"))?
        .clone();

    let serialize_and_sign = Node::new(
        Tag::signed(&message.name),
        NodeKind::Serialize {
            data: array.get_strong_ref(),
            group: group.clone(),
            adapter: message.serde_adapter.clone(),
        },
    );

    let send_node = Node::new(
        Tag::sent(&message.name),
        NodeKind::DirectMessage {
            data: serialize_and_sign,
            group,
        },
    );

    collect(&send_node)
}

fn deserialize<SP: SessionParameters>(
    args: Args<SP>,
    arg_name: &str,
    message: &ProtocolMessage<SP>,
) -> Result<Value, ComputeError> {
    let received = args.get::<SerializedValue>(arg_name)?;
    message
        .serde_adapter
        .deserialize(received)
        .map_err(|_err| ComputeError::Data)
}

pub fn receive<SP: SessionParameters>(message: &ProtocolMessage<SP>, group: &PartyGroup<SP::Verifier>) -> Node<SP> {
    let received = Node::new(Tag::received(&message.name), NodeKind::Receive { group: group.clone() });

    let cloned_message = message.clone();
    let arg_name = "_value".to_string();

    Node::new(
        Tag::deserialized(&message.name),
        NodeKind::ComputeArray {
            args: [(arg_name.clone(), received)].into(),
            function: ArrayFunction::Public(WrappedArrayFunction::new_pre_erased(
                "deserialize",
                move |_id: &SP::Verifier, args: Args<SP>| deserialize::<SP>(args, &arg_name, &cloned_message),
            )),
            group: group.clone(),
        },
    )
}

pub fn collect<SP: SessionParameters>(values: &Node<SP>) -> Result<Node<SP>, LocalError> {
    let group = values
        .group()
        .ok_or_else(|| LocalError::new("`values` argument of `collect()` must be an array node"))?
        .clone();

    Ok(Node::new(
        values.store_in().collected(),
        NodeKind::Collect {
            values: values.get_strong_ref(),
            group,
        },
    ))
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub struct ProtocolMessage<SP: SessionParameters> {
    name: String,
    serde_adapter: SerdeAdapter<SP::WireFormat>,
}

impl<SP: SessionParameters> ProtocolMessage<SP> {
    pub fn new<T: Erasable + Serialize + for<'de> Deserialize<'de>>(name: &str) -> Self {
        Self {
            name: name.into(),
            serde_adapter: SerdeAdapter::new::<T>(),
        }
    }
}

// TODO: can we avoid passing `my_id` explicitly?
pub fn call_protocol<SP: SessionParameters, P: ComposableProtocol<SP>>(
    prefix: &str,
    my_id: &SP::Verifier,
    build_data: &P::BuildData,
    args: ProtocolArgs<SP>,
) -> Result<Node<SP>, LocalError> {
    let signature = P::signature();
    let (aliased_args, original_nodes) = args.with_aliases(signature)?;
    let output = P::build(my_id, build_data, aliased_args)?;
    Ok(output.with_added_prefix(prefix, original_nodes))
}
