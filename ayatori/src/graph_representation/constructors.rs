use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
};

use serde::{Deserialize, Serialize};
use signature::rand_core::CryptoRngCore;

use super::{
    args::{ArgNodes, PartyBuildData, ProtocolArgs},
    node::{Node, NodeKind, args_to_owned},
};
use crate::{
    entities::{
        AnyTagRef, Args, AssociatedData, ComputedMappingTag, ComputedScalarTag, DeserializeArgs, DeserializeFunction,
        Erasable, FullName, InfallibleMappingFunction, InfallibleMappingFunctionWithRng, InfallibleScalarFunction,
        InfallibleScalarFunctionWithRng, LocalSignedTag, MappingFunction, PartyGroup, RemoteSignedTag,
        ScalarArgumentTag, ScalarFunction, SenderAttributableMappingFunction, SenderError, SerdeAdapter,
        SerializeAndSignFunction, SerializeArgs, SignedValue, ThirdPartyAttributableMappingFunction,
        ThirdPartyAttributableVerificationFunction, ThirdPartyError, Value,
    },
    errors::LocalError,
    execution::{EvidenceError, SessionId},
    traits::{ComposableProtocol, SessionParameters},
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
    Node::new(NodeKind::ScalarArgument {
        store_in: ScalarArgumentTag::new(name),
        name: name.to_string(),
    })
}

pub fn constant<SP: SessionParameters, Ret: Erasable>(name: &str, value: Ret) -> Node<SP> {
    let erased_value = Value::new(value);
    Node::new(NodeKind::ComputeScalar {
        store_in: ComputedScalarTag::new(name),
        function: ScalarFunction::Infallible(InfallibleScalarFunction::new_with_name(name, move |_args| {
            Ok(erased_value.clone())
        })),
        args: BTreeMap::new(),
    })
}

pub fn alias<SP: SessionParameters>(name: &str, node: &Node<SP>) -> Node<SP> {
    let arg_name = "value";
    match node.store_in() {
        AnyTagRef::Mapping(_) => Node::new(NodeKind::ComputeMapping {
            store_in: ComputedMappingTag::new(name),
            function: MappingFunction::Infallible(InfallibleMappingFunction::new_with_name(
                "alias",
                move |_id, args| args.get_value(arg_name).cloned(),
            )),
            args: [(arg_name.into(), node.get_strong_ref())].into(),
        }),
        AnyTagRef::Scalar(_) => Node::new(NodeKind::ComputeScalar {
            store_in: ComputedScalarTag::new(name),
            function: ScalarFunction::Infallible(InfallibleScalarFunction::new_with_name("alias", move |args| {
                args.get_value(arg_name).cloned()
            })),
            args: [(arg_name.into(), node.get_strong_ref())].into(),
        }),
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
            if !args.iter().all(|(_name, arg)| arg.store_in().scalar().is_some()) {
                return Err(LocalError::new(
                    "Scalar computations may only take scalar nodes as arguments"
                ));
            }

            Ok(Node::new(
                NodeKind::ComputeScalar {
                    store_in: ComputedScalarTag::new(name),
                    function: $outer_type::$outer_ctr($inner_type::new_erased(function)),
                    args: args_to_owned(args.iter().cloned())?,
                },
            ))
        }
    }
}

macro_rules! define_mapping_constructor {
    ($func_name:ident<$SP:ident>, $outer_type:ident::$outer_ctr:ident($inner_type:ident),
        ($($arg_type:ty),+) -> $error_type:ty ) =>
    {
        pub fn $func_name<$SP: SessionParameters, Ret: Erasable>(
            name: &str,
            function: impl 'static + Fn($($arg_type),*) -> Result<Ret, $error_type>,
            args: &[(&str, &Node<$SP>)],
        ) -> Result<Node<$SP>, LocalError> {
            Ok(Node::new(
                NodeKind::ComputeMapping {
                    store_in: ComputedMappingTag::new(name),
                    function: $outer_type::$outer_ctr($inner_type::new_erased(function)),
                    args: args_to_owned(args.iter().cloned())?,
                },
            ))
        }
    }
}

define_scalar_constructor!(
    compute_scalar<SP>,
    ScalarFunction::Infallible(InfallibleScalarFunction),
    (&Args<SP>) -> LocalError
);

define_scalar_constructor!(
    compute_scalar_with_rng<SP>,
    ScalarFunction::InfallibleWithRng(InfallibleScalarFunctionWithRng),
    (&mut dyn CryptoRngCore, &Args<SP>) -> LocalError
);

define_mapping_constructor!(
    compute_mapping<SP>,
    MappingFunction::Infallible(InfallibleMappingFunction),
    (&SP::Verifier, &Args<SP>) -> LocalError
);

define_mapping_constructor!(
    compute_mapping_sender_fallible<SP>,
    MappingFunction::SenderAttributable(SenderAttributableMappingFunction),
    (&SP::Verifier, &Args<SP>) -> SenderError
);

define_mapping_constructor!(
    compute_mapping_with_rng<SP>,
    MappingFunction::InfallibleWithRng(InfallibleMappingFunctionWithRng),
    (&mut dyn CryptoRngCore, &SP::Verifier, &Args<SP>) -> LocalError
);

pub fn compute_mapping_third_party_fallible<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, ThirdPartyError<SP>>,
    args: &[(&str, &Node<SP>)],
    verification: impl 'static + Fn(&SessionId<SP>, &SP::Verifier, &AssociatedData<SP>) -> Result<(), EvidenceError>,
) -> Result<Node<SP>, LocalError> {
    Ok(Node::new(NodeKind::ComputeMapping {
        store_in: ComputedMappingTag::new(name),
        function: MappingFunction::ThirdPartyAttributable {
            function: ThirdPartyAttributableMappingFunction::new_erased(function),
            verification: ThirdPartyAttributableVerificationFunction::new(verification),
        },
        args: args_to_owned(args.iter().cloned())?,
    }))
}

fn default_serialize_and_sign<SP: SessionParameters>(
    rng: &mut dyn CryptoRngCore,
    destination: &SP::Verifier,
    args: &SerializeArgs<SP>,
) -> Result<Value, LocalError> {
    let serialized_value = args.serde_adapter().serialize(args.value())?;
    let signed_value = SignedValue::<SP>::new(
        rng,
        args.signer(),
        args.session_id(),
        args.message_name(),
        destination,
        serialized_value,
    )?;
    Ok(Value::new(signed_value))
}

pub fn broadcast<SP: SessionParameters>(
    message: &ProtocolMessage<SP>,
    scalar: &Node<SP>,
    group: &PartyGroup<SP::Verifier>,
) -> Result<Node<SP>, LocalError> {
    if scalar.store_in().scalar().is_none() {
        return Err(LocalError::new(
            "`scalar` argument of `broadcast()` must be a scalar node",
        ));
    }

    let signed_tag = LocalSignedTag::new(message.name());
    let sent_tag = signed_tag.to_sent();

    let serialize_and_sign = Node::new(NodeKind::SerializeAndSign {
        store_in: signed_tag,
        function: SerializeAndSignFunction::new(default_serialize_and_sign),
        data: scalar.get_strong_ref(),
        message_name: FullName::new(message.name()),
        serde_adapter: message.serde_adapter().clone(),
    });

    let send_node = Node::new(NodeKind::DirectMessage {
        store_in: sent_tag,
        data: serialize_and_sign,
    });

    collect(&send_node, group)
}

pub fn send<SP: SessionParameters>(
    message: &ProtocolMessage<SP>,
    mapping: &Node<SP>,
    group: &PartyGroup<SP::Verifier>,
) -> Result<Node<SP>, LocalError> {
    let signed_tag = LocalSignedTag::new(message.name());
    let sent_tag = signed_tag.to_sent();

    let serialize_and_sign = Node::new(NodeKind::SerializeAndSign {
        store_in: signed_tag,
        function: SerializeAndSignFunction::new(default_serialize_and_sign),
        data: mapping.get_strong_ref(),
        message_name: FullName::new(message.name()),
        serde_adapter: message.serde_adapter().clone(),
    });

    let send_node = Node::new(NodeKind::DirectMessage {
        store_in: sent_tag,
        data: serialize_and_sign,
    });

    collect(&send_node, group)
}

fn default_deserialize<SP: SessionParameters>(args: &DeserializeArgs<SP>) -> Result<Value, SenderError> {
    let verified_value = args.verified_value();

    let expected_senders = args.expected_senders().ok_or_else(SenderError::new)?;

    if !expected_senders.contains(verified_value.source()) {
        return Err(SenderError::new());
    }

    let value = args
        .serde_adapter()
        .deserialize(verified_value.serialized_value())
        .map_err(|_err| SenderError::new())?;

    Ok(value)
}

pub fn receive_split<SP: SessionParameters>(message: &ProtocolMessage<SP>) -> Result<(Node<SP>, Node<SP>), LocalError> {
    let receive_store_in = RemoteSignedTag::new(message.name());
    let deserialize_store_in = receive_store_in.to_received();
    let message_name = FullName::new(message.name());

    let receive = Node::new(NodeKind::Receive {
        store_in: receive_store_in,
        message_name,
    });

    let deserialize = Node::new(NodeKind::Deserialize {
        store_in: deserialize_store_in,
        function: DeserializeFunction::new(default_deserialize),
        data: receive.get_strong_ref(),
        serde_adapter: message.serde_adapter().clone(),
    });

    Ok((receive, deserialize))
}

pub fn receive<SP: SessionParameters>(message: &ProtocolMessage<SP>) -> Result<Node<SP>, LocalError> {
    receive_split(message).map(|(_receive, deserialize)| deserialize)
}

pub fn collect<SP: SessionParameters>(
    values: &Node<SP>,
    group: &PartyGroup<SP::Verifier>,
) -> Result<Node<SP>, LocalError> {
    let store_in = values
        .store_in()
        .mapping()
        .ok_or_else(|| LocalError::new("`values` argument of `collect()` must be a mapping node"))?;
    Ok(Node::new(NodeKind::Collect {
        store_in: store_in.to_collected(),
        values: values.get_strong_ref(),
        group: group.clone(),
    }))
}

pub fn call_protocol<SP: SessionParameters, P: ComposableProtocol<SP>>(
    prefix: &str,
    party_build_data: &PartyBuildData<SP>,
    build_data: &P::BuildData,
    args: ProtocolArgs<SP>,
) -> Result<Node<SP>, LocalError> {
    let signature = P::signature();
    let arg_nodes = ArgNodes::new(&signature);
    let output = P::build(party_build_data, build_data, arg_nodes)?;
    let prefixed = output.tree_with_added_prefix(prefix);
    let bound_args = signature.bind(args)?;
    let with_args = prefixed.with_substituted_arguments(bound_args)?;
    Ok(with_args)
}
