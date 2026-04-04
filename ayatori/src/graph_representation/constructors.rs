use alloc::{
    collections::BTreeMap,
    format,
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
        Erasable, EvidenceVerdict, EvidenceVerificationFunction, FullName, LocalSignedTag, MappingFunction, PartyGroup,
        RemoteSignedTag, RuntimeError, ScalarArgumentTag, ScalarFunction, SenderAttributableError,
        SenderAttributableErrorWithReveal, SenderAttributableMappingFunction,
        SenderAttributableWithRevealMappingFunction, SerdeAdapter, SerializeAndSignFunction, SerializeArgs, SessionId,
        SignedValue, ThirdPartyAttributableError, ThirdPartyAttributableMappingFunction,
        ThirdPartyAttributableVerificationFunction, UnattributableError, UnattributableMappingFunction,
        UnattributableMappingFunctionWithRng, UnattributableScalarFunction, UnattributableScalarFunctionWithRng, Value,
    },
    traits::{ComposableProtocol, SessionParameters},
};

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub struct ProtocolMessage<SP: SessionParameters> {
    name: String,
    serde_adapter: SerdeAdapter<SP::WireFormat>,
}

impl<SP: SessionParameters> ProtocolMessage<SP> {
    #[must_use]
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
        function: ScalarFunction::Unattributable(UnattributableScalarFunction::new_with_name(name, move |_args| {
            Ok(erased_value.clone())
        })),
        args: BTreeMap::new(),
    })
}

#[must_use]
pub fn alias<SP: SessionParameters>(name: &str, node: &Node<SP>) -> Node<SP> {
    let arg_name = "value";
    match node.store_in() {
        AnyTagRef::Mapping(_) => Node::new(NodeKind::ComputeMapping {
            store_in: ComputedMappingTag::new(name),
            function: MappingFunction::Unattributable(UnattributableMappingFunction::new_with_name(
                "alias",
                move |_id, args| Ok(args.get_value(arg_name)?.clone()),
            )),
            args: [(arg_name.into(), node.get_strong_ref())].into(),
        }),
        AnyTagRef::Scalar(_) => Node::new(NodeKind::ComputeScalar {
            store_in: ComputedScalarTag::new(name),
            function: ScalarFunction::Unattributable(UnattributableScalarFunction::new_with_name(
                "alias",
                move |args| Ok(args.get_value(arg_name)?.clone()),
            )),
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
        ) -> Result<Node<$SP>, RuntimeError> {
            if !args.iter().all(|(_name, arg)| arg.store_in().scalar().is_some()) {
                return Err(RuntimeError::new(
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
        ) -> Result<Node<$SP>, RuntimeError> {
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
    ScalarFunction::Unattributable(UnattributableScalarFunction),
    (&Args<SP>) -> UnattributableError
);

define_scalar_constructor!(
    compute_scalar_with_rng<SP>,
    ScalarFunction::UnattributableWithRng(UnattributableScalarFunctionWithRng),
    (&mut dyn CryptoRngCore, &Args<SP>) -> UnattributableError
);

define_mapping_constructor!(
    compute_mapping<SP>,
    MappingFunction::Unattributable(UnattributableMappingFunction),
    (&SP::Verifier, &Args<SP>) -> UnattributableError
);

define_mapping_constructor!(
    compute_mapping_sender_fallible<SP>,
    MappingFunction::SenderAttributable(SenderAttributableMappingFunction),
    (&SP::Verifier, &Args<SP>) -> SenderAttributableError
);

define_mapping_constructor!(
    compute_mapping_with_rng<SP>,
    MappingFunction::UnattributableWithRng(UnattributableMappingFunctionWithRng),
    (&mut dyn CryptoRngCore, &SP::Verifier, &Args<SP>) -> UnattributableError
);

pub fn compute_mapping_third_party_fallible<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, ThirdPartyAttributableError<SP>>,
    args: &[(&str, &Node<SP>)],
    verification: impl 'static
    + Fn(&SP::Verifier, &SessionId<SP>, &AssociatedData<SP>) -> Result<EvidenceVerdict, RuntimeError>,
) -> Result<Node<SP>, RuntimeError> {
    Ok(Node::new(NodeKind::ComputeMapping {
        store_in: ComputedMappingTag::new(name),
        function: MappingFunction::ThirdPartyAttributable {
            function: ThirdPartyAttributableMappingFunction::new_erased(function),
            verification: ThirdPartyAttributableVerificationFunction::new(verification),
        },
        args: args_to_owned(args.iter().copied())?,
    }))
}

pub fn compute_mapping_sender_fallible_with_info<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, SenderAttributableErrorWithReveal<SP>>,
    args: &[(&str, &Node<SP>)],
    verification: impl 'static + Fn(&SP::Verifier, &Args<SP>, &AssociatedData<SP>) -> Result<EvidenceVerdict, RuntimeError>,
    verification_args: &[(&str, &Node<SP>)],
) -> Result<Node<SP>, RuntimeError> {
    Ok(Node::new(NodeKind::ComputeMappingSenderAttributableWithReveal {
        store_in: ComputedMappingTag::new(name),
        function: SenderAttributableWithRevealMappingFunction::new_erased(function),
        verification: EvidenceVerificationFunction::new(verification),
        args: args_to_owned(args.iter().copied())?,
        verification_args: args_to_owned(verification_args.iter().copied())?,
    }))
}

fn default_serialize_and_sign<SP: SessionParameters>(
    rng: &mut dyn CryptoRngCore,
    destination: &SP::Verifier,
    args: &SerializeArgs<SP>,
) -> Result<Value, RuntimeError> {
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
) -> Result<Node<SP>, RuntimeError> {
    if scalar.store_in().scalar().is_none() {
        return Err(RuntimeError::new(
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
) -> Result<Node<SP>, RuntimeError> {
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

fn default_deserialize<SP: SessionParameters>(args: &DeserializeArgs<SP>) -> Result<Value, SenderAttributableError> {
    let verified_value = args.verified_value();

    let expected_senders = args.expected_senders();

    if !expected_senders.contains(verified_value.source()) {
        return Err(SenderAttributableError::new(format!(
            "Expected senders do not include {:?}",
            verified_value.source()
        )));
    }

    let value = args
        .serde_adapter()
        .deserialize(verified_value.serialized_value())
        .map_err(|error| SenderAttributableError::new(format!("Failed to deserialize the value: {error}")))?;

    Ok(value)
}

pub fn receive_split<SP: SessionParameters>(
    message: &ProtocolMessage<SP>,
) -> Result<(Node<SP>, Node<SP>), RuntimeError> {
    let receive_store_in = RemoteSignedTag::new(message.name());
    let deserialize_store_in = receive_store_in.to_received();
    let message_name = FullName::new(message.name());

    let receive = Node::new(NodeKind::Receive {
        store_in: receive_store_in,
        message_name: message_name.clone(),
    });

    let deserialize = Node::new(NodeKind::Deserialize {
        store_in: deserialize_store_in,
        function: DeserializeFunction::new(default_deserialize),
        data: receive.get_strong_ref(),
        message_name,
        serde_adapter: message.serde_adapter().clone(),
    });

    Ok((receive, deserialize))
}

pub fn receive<SP: SessionParameters>(message: &ProtocolMessage<SP>) -> Result<Node<SP>, RuntimeError> {
    receive_split(message).map(|(_receive, deserialize)| deserialize)
}

pub fn collect<SP: SessionParameters>(
    values: &Node<SP>,
    group: &PartyGroup<SP::Verifier>,
) -> Result<Node<SP>, RuntimeError> {
    let store_in = values
        .store_in()
        .mapping()
        .ok_or_else(|| RuntimeError::new("`values` argument of `collect()` must be a mapping node"))?;
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
) -> Result<Node<SP>, RuntimeError> {
    let signature = P::signature();
    let arg_nodes = ArgNodes::new(&signature);
    let output = P::build(party_build_data, build_data, arg_nodes)?;
    let prefixed = output.tree_with_added_prefix(prefix);
    let bound_args = signature.bind(args)?;
    let with_args = prefixed.with_substituted_arguments(&bound_args)?;
    Ok(with_args)
}
