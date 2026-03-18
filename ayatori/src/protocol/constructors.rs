use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use serde::{Deserialize, Serialize};
use signature::rand_core::CryptoRngCore;

use super::{
    args::{ArgNodes, Args, ProtocolArgs},
    function::{
        ArrayFunction, InfallibleArrayFunction, InfallibleArrayFunctionWithRng, InfallibleArrayFunctionWithSigner,
        InfallibleScalarFunction, InfallibleScalarFunctionWithRng, ScalarFunction, SenderAttributableArrayFunction,
        SenderError, ThirdPartyAttributableArrayFunction, ThirdPartyError,
    },
    node::{Node, NodeKind, args_to_owned},
    party::PartyGroup,
    tag::{ArrayTag, FullName, ScalarTag},
    traits::{ComposableProtocol, SessionParameters},
    value::{Erasable, SerdeAdapter, Value},
};
use crate::{
    error::LocalError,
    session::{SignedValue, VerifiedValue},
};

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

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn serde_adapter(&self) -> &SerdeAdapter<SP::WireFormat> {
        &self.serde_adapter
    }
}

pub(crate) fn scalar_argument<SP: SessionParameters>(name: &str) -> Node<SP> {
    Node::new(
        // TODO (#62): a special tag type?
        NodeKind::ScalarArgument {
            store_in: ScalarTag::computed(name),
            name: name.to_string(),
        },
    )
}

pub fn constant<SP: SessionParameters, Ret: Erasable>(name: &str, value: Ret) -> Node<SP> {
    let erased_value = Value::new(value);
    Node::new(NodeKind::ComputeScalar {
        store_in: ScalarTag::computed(name),
        function: ScalarFunction::Infallible(InfallibleScalarFunction::new_pre_erased(name, move |_args| {
            Ok(erased_value.clone())
        })),
        args: BTreeMap::new(),
    })
}

pub fn alias<SP: SessionParameters>(name: &str, node: &Node<SP>) -> Node<SP> {
    let arg_name = "value";
    if let Some(group) = node.group() {
        Node::new(NodeKind::ComputeArray {
            store_in: ArrayTag::computed(name),
            function: ArrayFunction::Infallible(InfallibleArrayFunction::new_pre_erased("alias", move |_id, args| {
                args.get_value(arg_name).cloned()
            })),
            args: [(arg_name.into(), node.get_strong_ref())].into(),
            group: group.clone(),
        })
    } else {
        Node::new(NodeKind::ComputeScalar {
            store_in: ScalarTag::computed(name),
            function: ScalarFunction::Infallible(InfallibleScalarFunction::new_pre_erased("alias", move |args| {
                args.get_value(arg_name).cloned()
            })),
            args: [(arg_name.into(), node.get_strong_ref())].into(),
        })
    }
}

macro_rules! define_scalar_constructor {
    ($func_name:ident<$SP:ident>, $outer_type:ident::$outer_ctr:ident($inner_type:ident),
        ($($arg_type:ty),+) -> $error_type:ty ) =>
    {
        pub fn $func_name<$SP: SessionParameters, Ret: Erasable>(
            name: &str,
            function: impl 'static + Fn($($arg_type),*) -> Result<Ret, $error_type>,
            args: &[(&str, &Node<$SP>)],
        ) -> Result<Node<$SP>, LocalError> {
            if !args.iter().all(|(_name, arg)| arg.group().is_none()) {
                return Err(LocalError::new(
                    "Scalar computations may only take scalar nodes as arguments"
                ));
            }

            Ok(Node::new(
                NodeKind::ComputeScalar {
                    store_in: ScalarTag::computed(name),
                    function: $outer_type::$outer_ctr($inner_type::new(function)),
                    args: args_to_owned(args.iter().cloned())?,
                },
            ))
        }
    }
}

macro_rules! define_array_constructor {
    ($func_name:ident<$SP:ident>, $outer_type:ident::$outer_ctr:ident($inner_type:ident),
        ($($arg_type:ty),+) -> $error_type:ty ) =>
    {
        pub fn $func_name<$SP: SessionParameters, Ret: Erasable>(
            name: &str,
            function: impl 'static + Fn($($arg_type),*) -> Result<Ret, $error_type>,
            group: &PartyGroup<SP::Verifier>,
            args: &[(&str, &Node<$SP>)],
        ) -> Result<Node<$SP>, LocalError> {
            let arg_groups = args.iter().filter_map(|(_name, arg)| arg.group()).collect::<Vec<_>>();
            if arg_groups.iter().any(|g| g != &group) {
                return Err(LocalError::new(
                    "The group of all arguments must be equal to the one provided to the constructor"
                ));
            }

            Ok(Node::new(
                NodeKind::ComputeArray {
                    store_in: ArrayTag::computed(name),
                    function: $outer_type::$outer_ctr($inner_type::new(function)),
                    args: args_to_owned(args.iter().cloned())?,
                    group: group.clone(),
                },
            ))
        }
    }
}

define_scalar_constructor!(
    compute_scalar<SP>,
    ScalarFunction::Infallible(InfallibleScalarFunction),
    (Args<SP>) -> LocalError
);

define_scalar_constructor!(
    compute_scalar_with_rng<SP>,
    ScalarFunction::InfallibleWithRng(InfallibleScalarFunctionWithRng),
    (&mut dyn CryptoRngCore, Args<SP>) -> LocalError
);

define_array_constructor!(
    compute_array<SP>,
    ArrayFunction::Infallible(InfallibleArrayFunction),
    (&SP::Verifier, Args<SP>) -> LocalError
);

define_array_constructor!(
    compute_array_sender_fallible<SP>,
    ArrayFunction::SenderAttributable(SenderAttributableArrayFunction),
    (&SP::Verifier, Args<SP>) -> SenderError
);

define_array_constructor!(
    compute_array_third_party_fallible<SP>,
    ArrayFunction::ThirdPartyAttributable(ThirdPartyAttributableArrayFunction),
    (&SP::Verifier, Args<SP>) -> ThirdPartyError<SP>
);

define_array_constructor!(
    compute_array_with_rng<SP>,
    ArrayFunction::InfallibleWithRng(InfallibleArrayFunctionWithRng),
    (&mut dyn CryptoRngCore, &SP::Verifier, Args<SP>) -> LocalError
);

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
    signer: &SP::Signer,
    id: &SP::Verifier,
    args: Args<SP>,
    arg_name: &str,
    serde_adapter: &SerdeAdapter<SP::WireFormat>,
) -> Result<Value, LocalError> {
    let value = args.get_value(arg_name)?;
    let serialized_value = serde_adapter.serialize(value)?;
    let mut typed_rng = Rng(rng);
    let signed_value = SignedValue::<SP>::new(
        &mut typed_rng,
        signer,
        args.session_id(),
        args.store_in_name(),
        id,
        serialized_value,
    )?;
    Ok(Value::new(signed_value))
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

    let arg_name = "_value".to_string();
    let serde_adapter = message.serde_adapter().clone();
    let args = [(arg_name.clone(), scalar.get_strong_ref())].into();
    let tag = ArrayTag::signed_local(message.name());

    let serialize_and_sign = Node::new(NodeKind::ComputeArray {
        store_in: tag.clone(),
        function: ArrayFunction::InfallibleWithSigner(InfallibleArrayFunctionWithSigner::new_pre_erased(
            "serialize",
            move |rng, signer, id, args| serialize(rng, signer, id, args, &arg_name, &serde_adapter),
        )),
        group: group.clone(),
        args,
    });

    let send_node = Node::new(NodeKind::DirectMessage {
        store_in: tag.to_sent()?,
        data: serialize_and_sign,
        group: group.clone(),
    });

    collect(&send_node)
}

pub fn send<SP: SessionParameters>(message: &ProtocolMessage<SP>, array: &Node<SP>) -> Result<Node<SP>, LocalError> {
    let group = array
        .group()
        .ok_or_else(|| LocalError::new("`array` argument of `send()` must be an array node"))?
        .clone();

    let arg_name = "_value".to_string();
    let serde_adapter = message.serde_adapter().clone();
    let args = [(arg_name.clone(), array.get_strong_ref())].into();
    let tag = ArrayTag::signed_local(message.name());

    let serialize_and_sign = Node::new(NodeKind::ComputeArray {
        store_in: tag.clone(),

        function: ArrayFunction::InfallibleWithSigner(InfallibleArrayFunctionWithSigner::new_pre_erased(
            "serialize",
            move |rng, signer, id, args| serialize(rng, signer, id, args, &arg_name, &serde_adapter),
        )),
        group: group.clone(),
        args,
    });

    let send_node = Node::new(NodeKind::DirectMessage {
        store_in: tag.to_sent()?,
        data: serialize_and_sign,
        group,
    });

    collect(&send_node)
}

fn deserialize<SP: SessionParameters>(
    id: &SP::Verifier,
    args: Args<SP>,
    arg_name: &str,
    serde_adapter: &SerdeAdapter<SP::WireFormat>,
) -> Result<Value, SenderError> {
    let received = args.get::<VerifiedValue<SP>>(arg_name)?;

    let expected_senders = args
        .session_data()
        .expected_messages
        .get(args.store_in_name())
        .ok_or_else(SenderError::new)?;

    if !expected_senders.contains(id) {
        return Err(SenderError::new());
    }

    let value = serde_adapter
        .deserialize(received.serialized_value())
        .map_err(|_err| SenderError::new())?;

    Ok(value)
}

pub fn receive_signed<SP: SessionParameters>(
    message: &ProtocolMessage<SP>,
    group: &PartyGroup<SP::Verifier>,
) -> Node<SP> {
    Node::new(NodeKind::Receive {
        store_in: ArrayTag::signed_remote(message.name()),
        group: group.clone(),
        message_name: FullName::new(message.name()),
        serde_adapter: message.serde_adapter().clone(),
    })
}

pub fn deserialize_received<SP: SessionParameters>(received: &Node<SP>) -> Result<Node<SP>, LocalError> {
    let (store_in, group, serde_adapter) = match received.kind() {
        NodeKind::Receive {
            store_in,
            group,
            serde_adapter,
            ..
        } => (store_in, group, serde_adapter),
        _ => return Err(LocalError::new("The given node must be a Receive node")),
    };

    let arg_name = "_value".to_string();
    let serde_adapter = serde_adapter.clone();
    let args = [(arg_name.clone(), received.get_strong_ref())].into();

    Ok(Node::new(NodeKind::ComputeArray {
        store_in: store_in.to_received()?,
        function: ArrayFunction::SenderAttributable(SenderAttributableArrayFunction::new_pre_erased(
            "deserialize",
            move |id, args| deserialize(id, args, &arg_name, &serde_adapter),
        )),
        group: group.clone(),
        args,
    }))
}

pub fn receive<SP: SessionParameters>(
    message: &ProtocolMessage<SP>,
    group: &PartyGroup<SP::Verifier>,
) -> Result<Node<SP>, LocalError> {
    let received = receive_signed(message, group);
    deserialize_received(&received)
}

pub fn collect<SP: SessionParameters>(values: &Node<SP>) -> Result<Node<SP>, LocalError> {
    let (store_in, group) = values
        .store_in_and_group()
        .ok_or_else(|| LocalError::new("`values` argument of `collect()` must be an array node"))?;
    Ok(Node::new(NodeKind::Collect {
        store_in: store_in.collected(),
        values: values.get_strong_ref(),
        group: group.clone(),
    }))
}

pub fn call_protocol<SP: SessionParameters, P: ComposableProtocol<SP>>(
    prefix: &str,
    my_id: &SP::Verifier,
    build_data: &P::BuildData,
    args: ProtocolArgs<SP>,
) -> Result<Node<SP>, LocalError> {
    let signature = P::signature();
    let arg_nodes = ArgNodes::new(&signature);
    let output = P::build(my_id, build_data, arg_nodes)?;
    let prefixed = output.tree_with_added_prefix(prefix);
    let bound_args = signature.bind(args)?;
    let with_args = prefixed.with_substituted_arguments(bound_args)?;
    Ok(with_args)
}
