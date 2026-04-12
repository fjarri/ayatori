use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};
use signature::rand_core::CryptoRngCore;

use super::{
    any_node::AnyNode,
    args::{ArgNodes, PartyBuildData, ProtocolArgs},
    typed_nodes::{
        Collect, ComputeMapping, ComputeMappingKind, ComputeScalar, DeserializeAndCheck, DirectMessage,
        GeneralizedNode, Node, Receive, ScalarArgument, SerializeAndSign,
    },
    unions::{BroadcastArg, CollectArg, ComputeMappingArg, ComputeScalarArg, DirectMessageArg},
};
use crate::{
    entities::{
        Args, AssociatedData, ComputedMappingTag, ComputedScalarTag, DeserializeArgs, DeserializeFunction, Erasable,
        EvidenceVerdict, EvidenceVerificationFunction, FullName, LocalSignedTag, PartyGroup, RemoteSignedTag,
        RuntimeError, ScalarArgumentTag, ScalarFunction, SenderAttributableError, SenderAttributableErrorWithReveal,
        SenderAttributableMappingFunction, SenderAttributableWithRevealMappingFunction, SerdeAdapter,
        SerializeAndSignFunction, SerializeArgs, SessionId, SignedValue, SimpleMappingFunction,
        ThirdPartyAttributableError, ThirdPartyAttributableMappingFunction, ThirdPartyAttributableVerificationFunction,
        UnattributableError, UnattributableMappingFunction, UnattributableMappingFunctionWithRng,
        UnattributableScalarFunction, UnattributableScalarFunctionWithRng, Value,
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

pub(crate) fn scalar_argument<SP: SessionParameters>(name: &str) -> Node<ScalarArgument<SP>> {
    Node::new(ScalarArgument {
        store_in: ScalarArgumentTag::new(name),
        name: name.into(),
        phantom: PhantomData,
    })
}

pub fn constant<SP: SessionParameters, Ret: Erasable>(name: &str, value: Ret) -> Node<ComputeScalar<SP>> {
    let erased_value = Value::new(value);
    Node::new(ComputeScalar {
        store_in: ComputedScalarTag::new(name),
        function: ScalarFunction::Unattributable(UnattributableScalarFunction::new_with_name(name, move |_args| {
            Ok(erased_value.clone())
        })),
        args: BTreeMap::new(),
        dependencies: Vec::new(),
    })
}

#[must_use]
pub fn scalar_alias<SP: SessionParameters>(
    name: &str,
    node: impl Into<ComputeScalarArg<SP>>,
) -> Node<ComputeScalar<SP>> {
    let arg_name = "value";
    Node::new(ComputeScalar {
        store_in: ComputedScalarTag::new(name),
        function: ScalarFunction::Unattributable(UnattributableScalarFunction::new_with_name("alias", move |args| {
            Ok(args.get_value(arg_name)?.clone())
        })),
        args: [(arg_name.into(), node.into())].into(),
        dependencies: Vec::new(),
    })
}

#[must_use]
pub fn mapping_alias<SP: SessionParameters>(
    name: &str,
    node: impl Into<ComputeMappingArg<SP>>,
) -> Node<ComputeMapping<SP>> {
    let arg_name = "value";
    Node::new(ComputeMapping {
        store_in: ComputedMappingTag::new(name),
        kind: ComputeMappingKind::Simple {
            function: SimpleMappingFunction::Unattributable(UnattributableMappingFunction::new_with_name(
                "alias",
                move |_id, args| Ok(args.get_value(arg_name)?.clone()),
            )),
        },
        args: [(arg_name.into(), node.into())].into(),
        dependencies: Vec::new(),
    })
}

#[derive_where::derive_where(Debug)]
pub struct ComputeScalarArgs<SP: SessionParameters>(BTreeMap<String, ComputeScalarArg<SP>>);

impl<SP: SessionParameters, const N: usize> From<&[(&str, ComputeScalarArg<SP>); N]> for ComputeScalarArgs<SP> {
    /// Note that this implementation will not check for repeating argument names.
    /// Only the last one will be actually stored.
    fn from(source: &[(&str, ComputeScalarArg<SP>); N]) -> Self {
        let mut args = BTreeMap::new();
        for (name, arg) in source.iter() {
            args.insert(name.to_string(), arg.get_strong_ref());
        }
        Self(args)
    }
}

#[derive_where::derive_where(Debug)]
pub struct ComputeMappingArgs<SP: SessionParameters>(BTreeMap<String, ComputeMappingArg<SP>>);

impl<SP: SessionParameters, const N: usize> From<&[(&str, ComputeMappingArg<SP>); N]> for ComputeMappingArgs<SP> {
    /// Note that this implementation will not check for repeating argument names.
    /// Only the last one will be actually stored.
    fn from(source: &[(&str, ComputeMappingArg<SP>); N]) -> Self {
        let mut args = BTreeMap::new();
        for (name, arg) in source.iter() {
            args.insert(name.to_string(), arg.get_strong_ref());
        }
        Self(args)
    }
}

pub fn compute_scalar<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&Args<SP>) -> Result<Ret, UnattributableError>,
    args: impl Into<ComputeScalarArgs<SP>>,
) -> Node<ComputeScalar<SP>> {
    let args: ComputeScalarArgs<SP> = args.into();
    Node::new(ComputeScalar {
        store_in: ComputedScalarTag::new(name),
        function: ScalarFunction::Unattributable(UnattributableScalarFunction::new_erased(function)),
        args: args.0,
        dependencies: Vec::new(),
    })
}

pub fn compute_scalar_with_rng<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, &Args<SP>) -> Result<Ret, UnattributableError>,
    args: impl Into<ComputeScalarArgs<SP>>,
) -> Node<ComputeScalar<SP>> {
    let args: ComputeScalarArgs<SP> = args.into();
    Node::new(ComputeScalar {
        store_in: ComputedScalarTag::new(name),
        function: ScalarFunction::UnattributableWithRng(UnattributableScalarFunctionWithRng::new_erased(function)),
        args: args.0,
        dependencies: Vec::new(),
    })
}

pub fn compute_mapping<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, UnattributableError>,
    args: impl Into<ComputeMappingArgs<SP>>,
) -> Node<ComputeMapping<SP>> {
    let args: ComputeMappingArgs<SP> = args.into();
    Node::new(ComputeMapping {
        store_in: ComputedMappingTag::new(name),
        kind: ComputeMappingKind::Simple {
            function: SimpleMappingFunction::Unattributable(UnattributableMappingFunction::new_erased(function)),
        },
        args: args.0,
        dependencies: Vec::new(),
    })
}

pub fn compute_mapping_sender_fallible<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, SenderAttributableError>,
    args: impl Into<ComputeMappingArgs<SP>>,
) -> Node<ComputeMapping<SP>> {
    let args: ComputeMappingArgs<SP> = args.into();
    Node::new(ComputeMapping {
        store_in: ComputedMappingTag::new(name),
        kind: ComputeMappingKind::Simple {
            function: SimpleMappingFunction::SenderAttributable(SenderAttributableMappingFunction::new_erased(
                function,
            )),
        },
        args: args.0,
        dependencies: Vec::new(),
    })
}

pub fn compute_mapping_with_rng<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&mut dyn CryptoRngCore, &SP::Verifier, &Args<SP>) -> Result<Ret, UnattributableError>,
    args: impl Into<ComputeMappingArgs<SP>>,
) -> Node<ComputeMapping<SP>> {
    let args: ComputeMappingArgs<SP> = args.into();
    Node::new(ComputeMapping {
        store_in: ComputedMappingTag::new(name),
        kind: ComputeMappingKind::Simple {
            function: SimpleMappingFunction::UnattributableWithRng(UnattributableMappingFunctionWithRng::new_erased(
                function,
            )),
        },
        args: args.0,
        dependencies: Vec::new(),
    })
}

pub fn compute_mapping_third_party_fallible<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, ThirdPartyAttributableError<SP>>,
    args: impl Into<ComputeMappingArgs<SP>>,
    verification: impl 'static
    + Fn(&SP::Verifier, &SessionId<SP>, &AssociatedData<SP>) -> Result<EvidenceVerdict, RuntimeError>,
) -> Node<ComputeMapping<SP>> {
    let args: ComputeMappingArgs<SP> = args.into();
    Node::new(ComputeMapping {
        store_in: ComputedMappingTag::new(name),
        kind: ComputeMappingKind::ThirdPartyAttributable {
            function: ThirdPartyAttributableMappingFunction::new_erased(function),
            verification: ThirdPartyAttributableVerificationFunction::new(verification),
        },
        args: args.0,
        dependencies: Vec::new(),
    })
}

pub fn compute_mapping_sender_fallible_with_reveal<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, SenderAttributableErrorWithReveal<SP>>,
    args: impl Into<ComputeMappingArgs<SP>>,
    verification: impl 'static + Fn(&SP::Verifier, &Args<SP>, &AssociatedData<SP>) -> Result<EvidenceVerdict, RuntimeError>,
    verification_args: impl Into<ComputeMappingArgs<SP>>,
) -> Node<ComputeMapping<SP>> {
    let args: ComputeMappingArgs<SP> = args.into();
    let verification_args: ComputeMappingArgs<SP> = verification_args.into();
    Node::new(ComputeMapping {
        store_in: ComputedMappingTag::new(name),
        kind: ComputeMappingKind::WithReveal {
            function: SenderAttributableWithRevealMappingFunction::new_erased(function),
            verification: EvidenceVerificationFunction::new(verification),
            verification_args: verification_args.0,
        },
        args: args.0,
        dependencies: Vec::new(),
    })
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
    scalar: impl Into<BroadcastArg<SP>>,
    group: &PartyGroup<SP::Verifier>,
) -> Node<Collect<SP>> {
    let scalar: BroadcastArg<SP> = scalar.into();
    let signed_tag = LocalSignedTag::new(message.name());
    let sent_tag = signed_tag.to_sent();

    let serialize_and_sign = Node::new(SerializeAndSign {
        store_in: signed_tag,
        function: SerializeAndSignFunction::new(default_serialize_and_sign),
        data: scalar.into(),
        message_name: FullName::new(message.name()),
        serde_adapter: message.serde_adapter().clone(),
        dependencies: Vec::new(),
    });

    let send_node = Node::new(DirectMessage {
        store_in: sent_tag,
        data: serialize_and_sign,
        dependencies: Vec::new(),
    });

    collect(CollectArg::DirectMessage(send_node), group)
}

pub fn direct_message<SP: SessionParameters>(
    message: &ProtocolMessage<SP>,
    data: impl Into<DirectMessageArg<SP>>,
    group: &PartyGroup<SP::Verifier>,
) -> Node<Collect<SP>> {
    let data: DirectMessageArg<SP> = data.into();
    let signed_tag = LocalSignedTag::new(message.name());
    let sent_tag = signed_tag.to_sent();

    let serialize_and_sign = Node::new(SerializeAndSign {
        store_in: signed_tag,
        function: SerializeAndSignFunction::new(default_serialize_and_sign),
        data: data.get_strong_ref(),
        message_name: FullName::new(message.name()),
        serde_adapter: message.serde_adapter().clone(),
        dependencies: Vec::new(),
    });

    let send_node = Node::new(DirectMessage {
        store_in: sent_tag,
        data: serialize_and_sign,
        dependencies: Vec::new(),
    });

    collect(CollectArg::DirectMessage(send_node), group)
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
) -> (Node<Receive<SP>>, Node<DeserializeAndCheck<SP>>) {
    let receive_store_in = RemoteSignedTag::new(message.name());
    let deserialize_store_in = receive_store_in.to_received();
    let message_name = FullName::new(message.name());

    let receive = Node::new(Receive {
        store_in: receive_store_in,
        message_name: message_name.clone(),
        dependencies: Vec::new(),
    });

    let deserialize = Node::new(DeserializeAndCheck {
        store_in: deserialize_store_in,
        function: DeserializeFunction::new(default_deserialize),
        data: receive.get_strong_ref(),
        message_name,
        serde_adapter: message.serde_adapter().clone(),
        dependencies: Vec::new(),
    });

    (receive, deserialize)
}

#[must_use]
pub fn receive<SP: SessionParameters>(message: &ProtocolMessage<SP>) -> Node<DeserializeAndCheck<SP>> {
    let (_receive, deserialize) = receive_split(message);
    deserialize
}

pub fn collect<SP: SessionParameters>(
    values: impl Into<CollectArg<SP>>,
    group: &PartyGroup<SP::Verifier>,
) -> Node<Collect<SP>> {
    let values = values.into();
    let store_in = values.store_in();
    Node::new(Collect {
        store_in: store_in.to_collected(),
        values,
        group: group.clone(),
        dependencies: Vec::new(),
    })
}

pub fn call_protocol<SP: SessionParameters, P: ComposableProtocol<SP>>(
    prefix: &str,
    party_build_data: &PartyBuildData<SP>,
    build_data: &P::BuildData,
    args: ProtocolArgs<SP>,
) -> Result<P::OutputNode, RuntimeError> {
    let signature = P::signature();
    let arg_nodes = ArgNodes::new(&signature);
    let output = P::build(party_build_data, build_data, arg_nodes)?;
    let any_node = Into::<AnyNode<SP>>::into(output).get_strong_ref();
    let prefixed = any_node.tree_with_added_prefix(prefix);
    let bound_args = signature.bind(args)?;
    let with_args = prefixed.with_substituted_arguments(&bound_args)?;
    let downcasted = P::OutputNode::try_from(with_args)
        .map_err(|_err| RuntimeError::new("Adding a prefix changed the root node type"))?;
    Ok(downcasted)
}
