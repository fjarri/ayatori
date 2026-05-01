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
        GeneralizedNode, MergeScalars, Node, Receive, ScalarArgument, SerializeAndSign,
    },
    unions::{BroadcastArg, CollectArg, ComputeMappingArg, ComputeScalarArg, DirectMessageArg},
};
use crate::{
    entities::{
        Args, AssociatedData, ComputedMappingTag, ComputedScalarTag, DeserializeArgs, DeserializeFunction, Erasable,
        EvidenceVerdict, FullName, LocalSignedTag, MergedScalarTag, OneOrBoth, PartyGroup, RemoteSignedTag,
        RuntimeError, ScalarArgumentTag, ScalarFunction, SenderAttributableError, SenderAttributableErrorWithReveal,
        SenderAttributableMappingFunction, SenderAttributableVerificationFunction,
        SenderAttributableWithRevealMappingFunction, SerdeAdapter, SerializeAndSignFunction, SerializeArgs, SessionId,
        SignedValue, SimpleMappingFunction, ThirdPartyAttributableError, ThirdPartyAttributableMappingFunction,
        ThirdPartyAttributableVerificationFunction, UnattributableError, UnattributableMappingFunction,
        UnattributableMappingFunctionWithRng, UnattributableOptionalScalarFunction, UnattributableScalarFunction,
        UnattributableScalarFunctionWithRng, Value,
    },
    traits::{ComposableProtocol, SessionParameters},
};

/// A typed message that can be sent to other parties.
#[derive_where::derive_where(Debug, Clone)]
pub struct ProtocolMessage<SP: SessionParameters> {
    name: String,
    serde_adapter: SerdeAdapter<SP::WireFormat>,
}

impl<SP: SessionParameters> ProtocolMessage<SP> {
    /// Declares a new message.
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

/// Creates a scalar node that returns `value` every time it is called.
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

/// Creates a scalar node that repackages another scalar node.
///
/// Used to attach dependencies to an externally passed node.
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

/// Creates a mapping node that repackages another mapping node.
///
/// Used to attach dependencies to an externally passed node.
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

/// A set of arguments to a [`ComputeScalar`] node.
#[derive_where::derive_where(Debug)]
pub struct ComputeScalarArgs<SP: SessionParameters>(BTreeMap<String, ComputeScalarArg<SP>>);

impl<SP: SessionParameters, const N: usize> From<&[(&str, ComputeScalarArg<SP>); N]> for ComputeScalarArgs<SP> {
    /// Note that this implementation will not check for repeating argument names.
    /// Only the last one will be actually stored.
    fn from(source: &[(&str, ComputeScalarArg<SP>); N]) -> Self {
        let mut args = BTreeMap::new();
        for (name, arg) in source {
            args.insert(name.to_string(), arg.get_strong_ref());
        }
        Self(args)
    }
}

/// A set of arguments to a [`ComputeMapping`] node.
#[derive_where::derive_where(Debug)]
pub struct ComputeMappingArgs<SP: SessionParameters>(BTreeMap<String, ComputeMappingArg<SP>>);

impl<SP: SessionParameters, const N: usize> From<&[(&str, ComputeMappingArg<SP>); N]> for ComputeMappingArgs<SP> {
    /// Note that this implementation will not check for repeating argument names.
    /// Only the last one will be actually stored.
    fn from(source: &[(&str, ComputeMappingArg<SP>); N]) -> Self {
        let mut args = BTreeMap::new();
        for (name, arg) in source {
            args.insert(name.to_string(), arg.get_strong_ref());
        }
        Self(args)
    }
}

/// Calls `function` and saves the result to the scalar slot `name`.
pub fn compute_scalar<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Send + Sync + Fn(&Args<SP>) -> Result<Ret, UnattributableError>,
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

/// Same as [`compute_scalar`], but `function` may use an RNG.
pub fn compute_scalar_with_rng<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Send + Sync + Fn(&mut dyn CryptoRngCore, &Args<SP>) -> Result<Ret, UnattributableError>,
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

fn fork_left<SP: SessionParameters, LRet: Erasable + Clone, RRet: Erasable + Clone>(
    lname: &str,
    fork: &Node<ComputeScalar<SP>>,
) -> Node<ComputeScalar<SP>> {
    let largs = ComputeScalarArgs::from(&[("fork", fork.into())]);
    Node::new(ComputeScalar {
        store_in: ComputedScalarTag::new(lname),
        function: ScalarFunction::UnattributableOptional(UnattributableOptionalScalarFunction::new(|args| {
            match args.get::<OneOrBoth<LRet, RRet>>("fork")? {
                OneOrBoth::Left(left) | OneOrBoth::Both { left, .. } => Ok(Some(Value::new(left.clone()))),
                OneOrBoth::Right(_) => Ok(None),
            }
        })),
        args: largs.0,
        dependencies: Vec::new(),
    })
}

fn fork_right<SP: SessionParameters, LRet: Erasable + Clone, RRet: Erasable + Clone>(
    rname: &str,
    fork: &Node<ComputeScalar<SP>>,
) -> Node<ComputeScalar<SP>> {
    let rargs = ComputeScalarArgs::from(&[("fork", fork.into())]);
    Node::new(ComputeScalar {
        store_in: ComputedScalarTag::new(rname),
        function: ScalarFunction::UnattributableOptional(UnattributableOptionalScalarFunction::new(|args| {
            match args.get::<OneOrBoth<LRet, RRet>>("fork")? {
                OneOrBoth::Right(right) | OneOrBoth::Both { right, .. } => Ok(Some(Value::new(right.clone()))),
                OneOrBoth::Left(_) => Ok(None),
            }
        })),
        args: rargs.0,
        dependencies: Vec::new(),
    })
}

/// Calls `function` and splits the result into two nodes, depending on the variant used in the return value.
///
/// Both `lname` and `rname` results may or may not be created (and therefore won't trigger any dependent nodes),
/// depending on what `function` returns.
pub fn compute_forked_scalar<SP: SessionParameters, LRet: Erasable + Clone, RRet: Erasable + Clone>(
    fork_name: &str,
    lname: &str,
    rname: &str,
    function: impl 'static + Send + Sync + Fn(&Args<SP>) -> Result<OneOrBoth<LRet, RRet>, UnattributableError>,
    args: impl Into<ComputeScalarArgs<SP>>,
) -> (Node<ComputeScalar<SP>>, Node<ComputeScalar<SP>>) {
    let fork = compute_scalar(fork_name, function, args);
    let lnode = fork_left::<SP, LRet, RRet>(lname, &fork);
    let rnode = fork_right::<SP, LRet, RRet>(rname, &fork);
    (lnode, rnode)
}

/// Same as [`compute_forked_scalar`], but `function` may use an RNG.
pub fn compute_forked_scalar_with_rng<SP: SessionParameters, LRet: Erasable + Clone, RRet: Erasable + Clone>(
    fork_name: &str,
    lname: &str,
    rname: &str,
    function: impl 'static
    + Send
    + Sync
    + Fn(&mut dyn CryptoRngCore, &Args<SP>) -> Result<OneOrBoth<LRet, RRet>, UnattributableError>,
    args: impl Into<ComputeScalarArgs<SP>>,
) -> (Node<ComputeScalar<SP>>, Node<ComputeScalar<SP>>) {
    let fork = compute_scalar_with_rng(fork_name, function, args);
    let lnode = fork_left::<SP, LRet, RRet>(lname, &fork);
    let rnode = fork_right::<SP, LRet, RRet>(rname, &fork);
    (lnode, rnode)
}

/// Calls `function` for a set of party IDs and saves the results to the mapping slot `name`.
///
/// The set of IDs it is called for is defined by the [`collect`] nodes downstream.
pub fn compute_mapping<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Send + Sync + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, UnattributableError>,
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

/// Same as [`compute_mapping`], but `function` may result in an error
/// caused by the data provided by the party with the ID it is called for.
pub fn compute_mapping_sender_fallible<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Send + Sync + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, SenderAttributableError>,
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

/// Same as [`compute_mapping`], but `function` may use an RNG.
pub fn compute_mapping_with_rng<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static
    + Send
    + Sync
    + Fn(&mut dyn CryptoRngCore, &SP::Verifier, &Args<SP>) -> Result<Ret, UnattributableError>,
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

/// Same as [`compute_mapping`], but `function` may result in an error caused by a third party
/// (that is, not the one which whose ID it is called).
pub fn compute_mapping_third_party_fallible<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static + Send + Sync + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, ThirdPartyAttributableError<SP>>,
    args: impl Into<ComputeMappingArgs<SP>>,
    verification: impl 'static
    + Send
    + Sync
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

/// Same as [`compute_mapping_sender_fallible`], but in case of sender-attributable error
/// it needs to reveal some additional piece of data to be attached to the evidence.
pub fn compute_mapping_sender_fallible_with_reveal<SP: SessionParameters, Ret: Erasable>(
    name: &str,
    function: impl 'static
    + Send
    + Sync
    + Fn(&SP::Verifier, &Args<SP>) -> Result<Ret, SenderAttributableErrorWithReveal<SP>>,
    args: impl Into<ComputeMappingArgs<SP>>,
    verification: impl 'static
    + Send
    + Sync
    + Fn(&SP::Verifier, &Args<SP>, &AssociatedData<SP>) -> Result<EvidenceVerdict, RuntimeError>,
    verification_args: impl Into<ComputeMappingArgs<SP>>,
) -> Node<ComputeMapping<SP>> {
    let args: ComputeMappingArgs<SP> = args.into();
    let verification_args: ComputeMappingArgs<SP> = verification_args.into();
    Node::new(ComputeMapping {
        store_in: ComputedMappingTag::new(name),
        kind: ComputeMappingKind::WithReveal {
            function: SenderAttributableWithRevealMappingFunction::new_erased(function),
            verification: SenderAttributableVerificationFunction::new(verification),
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

/// Broadcasts the scalar data with the type and name defined by `message` to all the nodes from `group`.
///
/// The return values are the collected outcomes of messages being sent (`()` on success).
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

/// Sends a direct message with the corresponding element from the given mapping,
/// and with the type and name defined by `message`, to all the nodes from `group`.
///
/// The return values are the collected outcomes of messages being sent (`()` on success).
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

/// Returns the result of [`receive`], along with the node containing the original signed value.
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

/// Returns the node for deserialized and checked message stripped of metadata.
#[must_use]
pub fn receive<SP: SessionParameters>(message: &ProtocolMessage<SP>) -> Node<DeserializeAndCheck<SP>> {
    let (_receive, deserialize) = receive_split(message);
    deserialize
}

/// Collects the elements of a mapping node into a scalar node.
pub fn collect<SP: SessionParameters>(
    values: impl Into<CollectArg<SP>>,
    group: &PartyGroup<SP::Verifier>,
) -> Node<Collect<SP>> {
    let values = values.into();
    let store_in = values.store_in().to_collected();
    Node::new(Collect {
        store_in,
        values,
        group: group.clone(),
        dependencies: Vec::new(),
    })
}

/// When `left`, or `right`, or both values are available, merges them into a single scalar value of type [`OneOrBoth`].
pub fn merge_scalars<SP: SessionParameters>(
    left: impl Into<ComputeScalarArg<SP>>,
    right: impl Into<ComputeScalarArg<SP>>,
) -> Node<MergeScalars<SP>> {
    let left: ComputeScalarArg<SP> = left.into();
    let right: ComputeScalarArg<SP> = right.into();
    let tag_name = format!("{}-or-{}", left.store_in(), right.store_in());
    let store_in = MergedScalarTag::new(&tag_name);
    Node::new(MergeScalars { store_in, left, right })
}

/// Builds a protocol and integrates it into the current graph.
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
