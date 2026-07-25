use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    vec::Vec,
};
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use ayatori::protocol_author_api::*;

use super::{
    merkle_tree::{MerkleBranch, MerkleTree},
    sharding::{self, FullShardSet, Scheme, Shard},
};

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
struct ValueMessage<SP: SessionParameters> {
    scheme: Scheme,
    shard: Shard,
    branch: MerkleBranch<SP::Digest>,
}

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
struct EchoMessage<SP: SessionParameters>(SignedValue<SP>);

fn make_shards<SP: SessionParameters, T: Erasable + Serialize>(
    args: &Args<SP>,
) -> Result<(Scheme, FullShardSet), UnattributableError> {
    let value = args.get::<T>("value")?;
    let threshold = args.get::<usize>("threshold")?;
    let ids = args.get::<BTreeSet<SP::Verifier>>("ids")?;
    let (scheme, shards) = sharding::new_set::<SP::WireFormat, _>(value, ids.len(), *threshold)?;
    Ok((scheme, shards))
}

fn make_merkle_tree<SP: SessionParameters>(args: &Args<SP>) -> Result<MerkleTree<SP::Digest>, UnattributableError> {
    let scheme_and_shards = args.get::<(Scheme, FullShardSet)>("scheme_and_shards")?;
    let tree = MerkleTree::new(scheme_and_shards.1.as_numbered_shards())?;
    Ok(tree)
}

fn make_value_message<SP: SessionParameters>(
    id: &SP::Verifier,
    args: &Args<SP>,
) -> Result<ValueMessage<SP>, UnattributableError> {
    let (scheme, shards) = args.get::<(Scheme, FullShardSet)>("scheme_and_shards")?;
    let merkle_tree = args.get::<MerkleTree<SP::Digest>>("merkle_tree")?;
    let ids_to_indices = args.get::<BTreeMap<SP::Verifier, usize>>("ids_to_indices")?;

    let idx = ids_to_indices
        .get(id)
        .ok_or_else(|| RuntimeError::new(format!("{id:?} not found in the list of all party IDs")))?;

    let shard = shards
        .as_ref()
        .get(*idx)
        .ok_or_else(|| RuntimeError::new(format!("{id:?} is expected to be present in the generated shards")))?
        .clone();
    let branch = merkle_tree.branch(*idx);
    Ok(ValueMessage {
        scheme: *scheme,
        shard,
        branch,
    })
}

fn make_echo<SP: SessionParameters>(args: &Args<SP>) -> Result<EchoMessage<SP>, UnattributableError> {
    let message_map = args.get_map::<VerifiedValue<SP>>("value_signed")?;
    let sender = args.get::<SP::Verifier>("sender")?;
    let message = message_map.get(sender).ok_or_else(|| {
        RuntimeError::new(format!(
            "Sender {sender:?} is expected to be present in received messages map"
        ))
    })?;
    let echo = EchoMessage((*message).clone().unverify());
    Ok(echo)
}

fn make_ids_to_indices<SP: SessionParameters>(
    args: &Args<SP>,
) -> Result<BTreeMap<SP::Verifier, usize>, UnattributableError> {
    let ids = args.get::<BTreeSet<SP::Verifier>>("ids")?;
    let ids_to_indices = ids
        .iter()
        .enumerate()
        .map(|(idx, id)| (id.clone(), idx))
        .collect::<BTreeMap<_, _>>();
    Ok(ids_to_indices)
}

#[derive_where::derive_where(Debug)]
struct OriginalMessage<SP: SessionParameters> {
    signed_value: SignedValue<SP>,
    value_message: ValueMessage<SP>,
}

fn make_original_message<SP: SessionParameters>(args: &Args<SP>) -> Result<OriginalMessage<SP>, UnattributableError> {
    let signed_value_map = args.get_map::<VerifiedValue<SP>>("value_signed")?;
    let message_map = args.get_map::<ValueMessage<SP>>("value")?;
    let sender = args.get::<SP::Verifier>("sender")?;

    let signed_value = signed_value_map.get(sender).ok_or_else(|| {
        RuntimeError::new(format!(
            "Sender {sender:?} is expected to be present in signed messages map"
        ))
    })?;

    let message = message_map.get(sender).ok_or_else(|| {
        RuntimeError::new(format!(
            "Sender {sender:?} is expected to be present in received messages map"
        ))
    })?;
    Ok(OriginalMessage {
        signed_value: (*signed_value).clone().unverify(),
        value_message: (*message).clone(),
    })
}

#[derive_where::derive_where(Debug)]
struct CheckedEchoMessage<SP: SessionParameters> {
    signed_value: SignedValue<SP>,
    serialized_value: SerializedValue,
}

fn check_echo<SP: SessionParameters>(
    _id: &SP::Verifier,
    args: &Args<SP>,
) -> Result<CheckedEchoMessage<SP>, MaybeAttributableError<SenderError>> {
    let sender = args.get::<SP::Verifier>("sender")?;
    let echo = args.get::<EchoMessage<SP>>("echo")?;

    if args.session_id() != echo.0.metadata().session_id() {
        return Err(SenderError::new("echo session ID is incorrect").into());
    }

    if echo.0.source() != sender {
        return Err(SenderError::new("echo source is incorrect").into());
    }

    // TODO (#93): check the message name. Note that it may be prefixed.
    // This may be done automatically when #93 is fixed.

    let Ok(serialized_value) = echo.0.clone().verify_and_unpack() else {
        return Err(SenderError::new("echo contains a message with an invalid signature").into());
    };

    Ok(CheckedEchoMessage {
        signed_value: echo.0.clone(),
        serialized_value,
    })
}

#[derive_where::derive_where(Debug, Clone)]
struct ProcessedEchoMessage<SP: SessionParameters> {
    signed_value: SignedValue<SP>,
    value_message: ValueMessage<SP>,
}

fn process_echo<SP: SessionParameters>(
    _id: &SP::Verifier,
    args: &Args<SP>,
) -> Result<ProcessedEchoMessage<SP>, MaybeAttributableError<ThirdPartyError<SP>>> {
    let sender = args.get::<SP::Verifier>("sender")?;
    let original_message = args.get::<OriginalMessage<SP>>("original_message")?;
    let echo = args.get::<CheckedEchoMessage<SP>>("echo")?;
    let ids_to_indices = args.get::<BTreeMap<SP::Verifier, usize>>("ids_to_indices")?;

    let error_package = (original_message.signed_value.clone(), echo.signed_value.clone());

    let Ok(value_message) = SP::WireFormat::deserialize::<ValueMessage<SP>>(echo.serialized_value.data()) else {
        return Err(ThirdPartyError::new("Failed to deserialize", sender, error_package)?.into());
    };

    if value_message.branch.root() != original_message.value_message.branch.root() {
        return Err(ThirdPartyError::new("Root mismatch", sender, error_package)?.into());
    }

    if value_message.scheme != original_message.value_message.scheme {
        return Err(ThirdPartyError::new("Scheme mismatch", sender, error_package)?.into());
    }

    let Some(id) = echo.signed_value.metadata().destination() else {
        return Err(ThirdPartyError::new(
            "The echoed value is supposed to have a non-None destination",
            sender,
            error_package,
        )?
        .into());
    };
    let idx = ids_to_indices
        .get(id)
        .ok_or_else(|| RuntimeError::new(format!("{id:?} not found in the list of all party IDs")))?;
    if !value_message.branch.verify(*idx, &value_message.shard) {
        return Err(ThirdPartyError::new("Branch verification failed", sender, error_package)?.into());
    }

    Ok(ProcessedEchoMessage {
        signed_value: echo.signed_value.clone(),
        value_message,
    })
}

fn verify_process_echo<SP: SessionParameters>(
    _guilty_party: &SP::Verifier,
    _session_id: &SessionId<SP>,
    _associated_data: &AssociatedData<SP>,
) -> Result<EvidenceVerdict, RuntimeError> {
    // TODO (#93): will not need this once the issue is fixed.
    todo!()
}

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
struct AssemblyError<SP: SessionParameters> {
    original_message: SignedValue<SP>,
    echoed_messages: Vec<SignedValue<SP>>,
}

fn interpolate_and_check_root<SP: SessionParameters>(
    args: &Args<SP>,
) -> Result<(), MaybeAttributableError<ThirdPartyError<SP>>> {
    let sender = args.get::<SP::Verifier>("sender")?;
    let original_message = args.get::<OriginalMessage<SP>>("original_message")?;
    let echoed_messages = args.get_map::<ProcessedEchoMessage<SP>>("processed_echos")?;

    let error_package = AssemblyError {
        original_message: original_message.signed_value.clone(),
        echoed_messages: echoed_messages
            .values()
            .map(|echo| echo.signed_value.clone())
            .collect::<Vec<_>>(),
    };

    // TODO (#93): re-attribution will happen here.

    let mut messages = BTreeMap::new();
    for echo_message in echoed_messages.values() {
        messages.insert(
            echo_message.signed_value.metadata().destination(),
            echo_message.value_message.clone(),
        );
    }

    let all_shards = sharding::interpolate(
        original_message.value_message.scheme,
        messages.values().map(|message| &message.shard),
    )?;
    let tree = MerkleTree::new(all_shards.as_numbered_shards())?;

    if &tree.root() != original_message.value_message.branch.root() {
        return Err(ThirdPartyError::new("Merkle root mismatch", sender, error_package)?.into());
    }

    Ok(())
}

fn verify_interpolate_and_check_root_error<SP: SessionParameters>(
    _guilty_party: &SP::Verifier,
    _session_id: &SessionId<SP>,
    _associated_data: &AssociatedData<SP>,
) -> Result<EvidenceVerdict, RuntimeError> {
    // TODO (#93): will not need this once the issue is fixed.
    todo!()
}

fn finalize<SP: SessionParameters, T: Erasable + for<'de> Deserialize<'de>>(
    args: &Args<SP>,
) -> Result<Option<T>, UnattributableError> {
    let original_message = args.get::<OriginalMessage<SP>>("original_message")?;
    let processed_echos = args.get_map::<ProcessedEchoMessage<SP>>("processed_echos")?;
    let value = sharding::assemble::<SP::WireFormat, T>(
        original_message.value_message.scheme,
        processed_echos.values().map(|echo| &echo.value_message.shard),
    )?;
    Ok(Some(value))
}

/// Build data for the RBC protocol
#[derive_where::derive_where(Debug, Clone)]
pub struct BuildData<SP: SessionParameters> {
    sender: SP::Verifier,
    receivers: BTreeSet<SP::Verifier>,
    max_faulty_parties: usize,
}

impl<SP: SessionParameters> BuildData<SP> {
    /// Creates the new build data.
    ///
    /// `sender` must be a member of `all_parties`.
    /// `max_faulty_parties` should be such that `max_faulty_parties * 2 + 1 <= len(all_parties)`
    pub fn new(
        receivers: &BTreeSet<SP::Verifier>,
        sender: &SP::Verifier,
        max_faulty_parties: usize,
    ) -> Result<Self, RuntimeError> {
        if receivers.len()
            < max_faulty_parties
                .checked_mul(2)
                .expect("no overflow")
                .checked_add(1)
                .expect("no overflow")
        {
            return Err(RuntimeError::new("`max_faulty_parties` is too large"));
        }

        Ok(Self {
            sender: sender.clone(),
            receivers: receivers.clone(),
            max_faulty_parties,
        })
    }

    #[cfg(test)]
    pub(crate) fn all_parties(&self) -> BTreeSet<SP::Verifier> {
        let mut result = self.receivers.clone();
        result.insert(self.sender.clone());
        result
    }
}

/// Reliable threshold broadcast protocol.
#[derive(Debug, Clone, Copy)]
pub struct ReliableBroadcast<T>(PhantomData<fn() -> T>);

impl<SP, T> ComposableProtocol<SP> for ReliableBroadcast<T>
where
    SP: SessionParameters,
    T: Erasable + Serialize + for<'de> Deserialize<'de>,
{
    type BuildData = BuildData<SP>;
    type OutputNode = Node<ComputeScalar<SP>>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new().input("to_broadcast")
    }

    fn build(
        party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        inputs: ArgNodes<SP>,
    ) -> Result<Self::OutputNode, RuntimeError> {
        let is_sender = &build_data.sender == party_build_data.id();
        let is_receiver = build_data.receivers.contains(party_build_data.id());

        let message_value = ProtocolMessage::new::<ValueMessage<SP>>("value");
        let message_echo = ProtocolMessage::new::<EchoMessage<SP>>("echo");
        let message_ready = ProtocolMessage::new::<()>("ready");

        let to_broadcast = inputs.get("to_broadcast")?;

        let n = build_data.receivers.len();
        let f = build_data.max_faulty_parties;

        let no_overflow = "no overflow as enforced by BuildData::new()";
        let echos_to_finalize = n.checked_sub(f.checked_mul(2).expect(no_overflow)).expect(no_overflow);
        let echos_to_check_root = n.checked_sub(f).expect(no_overflow);
        let readies_to_send_ready = f.checked_add(1).expect(no_overflow);
        let readies_to_finalize = f.checked_mul(2).expect(no_overflow).checked_add(1).expect(no_overflow);

        let ids = build_data.receivers.iter().cloned().collect::<Vec<_>>();
        let ids_set = constant("ids", ids.iter().cloned().collect::<BTreeSet<SP::Verifier>>());

        let ids_to_indices = compute_scalar("ids_to_indices", make_ids_to_indices, &[("ids", (&ids_set).into())]);

        let all_shards_sent = if is_sender {
            let threshold = constant("threshold", echos_to_finalize);
            let scheme_and_shards = compute_scalar(
                "scheme_and_shards",
                make_shards::<SP, T>,
                &[
                    ("value", (to_broadcast).into()),
                    ("threshold", (&threshold).into()),
                    ("ids", (&ids_set).into()),
                ],
            );
            let merkle_tree = compute_scalar(
                "merkle_tree",
                make_merkle_tree,
                &[("scheme_and_shards", (&scheme_and_shards).into())],
            );

            let value_messages = compute_mapping(
                "value_messages",
                make_value_message,
                &[
                    ("scheme_and_shards", (&scheme_and_shards).into()),
                    ("merkle_tree", (&merkle_tree).into()),
                    ("ids_to_indices", (&ids_to_indices).into()),
                ],
            );

            let shards_sent = direct_message(&message_value, &value_messages);
            // TODO (#27): the question of what threshold should be used here becomes moot when the issue is fixed.
            Dependency::from(&collect(&shards_sent, &ThresholdGroup::new(&ids)))
        } else {
            Dependency::from(&constant("empty_dependency", ()))
        };

        if is_receiver {
            let (value_signed, value_deserialized) = receive_split(&message_value);

            let sender = constant("sender", build_data.sender.clone());

            let sender_party = ThresholdGroup::new(core::slice::from_ref(&build_data.sender));
            let value_signed_scalar = collect(&value_signed, &sender_party).with_dependency(all_shards_sent);
            let value_deserialized_scalar = collect(&value_deserialized, &sender_party);

            let original_message = compute_scalar(
                "scheme",
                make_original_message,
                &[
                    ("sender", (&sender).into()),
                    ("value_signed", (&value_signed_scalar).into()),
                    ("value", (&value_deserialized_scalar).into()),
                ],
            );

            let echo = compute_scalar(
                "echo",
                make_echo,
                &[
                    ("sender", (&sender).into()),
                    ("value_signed", (&value_signed_scalar).into()),
                    ("ids", (&ids_set).into()),
                ],
            )
            .with_dependency(&value_deserialized_scalar);

            let echo_sent = broadcast(&message_echo, &echo, &build_data.receivers);
            let echo_received = receive(&message_echo);

            let echo_checked = compute_mapping_sender_fallible(
                "echo_checked",
                check_echo,
                &[("sender", (&sender).into()), ("echo", (&echo_received).into())],
            );

            let echo_processed = compute_mapping_third_party_fallible(
                "echo_processed",
                process_echo,
                &[
                    ("sender", (&sender).into()),
                    ("original_message", (&original_message).into()),
                    ("echo", (&echo_checked).into()),
                    ("ids_to_indices", (&ids_to_indices).into()),
                ],
                verify_process_echo,
            );

            let all_echos_to_check_root = collect_into(
                "to_check_root",
                &echo_processed,
                &ThresholdGroup::new_threshold(&ids, echos_to_check_root),
            )
            .with_dependency(&echo_sent);

            let root_checked = compute_scalar_third_party_attributable(
                "root_checked",
                interpolate_and_check_root,
                &[
                    ("processed_echos", (&all_echos_to_check_root).into()),
                    ("sender", (&sender).into()),
                    ("original_message", (&original_message).into()),
                ],
                verify_interpolate_and_check_root_error,
            );

            let ready_received = receive(&message_ready);

            let all_readies_to_send_ready = collect_into(
                "to_send_ready",
                &ready_received,
                &ThresholdGroup::new_threshold(&ids, readies_to_send_ready),
            );

            let send_ready_trigger = merge_scalars(&root_checked, &all_readies_to_send_ready);
            let ready = constant("ready", ());
            let ready_sent =
                broadcast(&message_ready, &ready, &build_data.receivers).with_dependency(&send_ready_trigger);

            let all_echos_to_finalize = collect_into(
                "echos_to_finalize",
                &echo_processed,
                &ThresholdGroup::new_threshold(&ids, echos_to_finalize),
            )
            .with_dependency(&echo_sent);

            let all_readies_to_finalize = collect_into(
                "readies_to_finalize",
                &ready_received,
                &ThresholdGroup::new_threshold(&ids, readies_to_finalize),
            );

            let finalize_trigger = merge_scalars(&all_echos_to_finalize, &all_readies_to_finalize);

            let output = compute_scalar(
                "output",
                finalize::<SP, T>,
                &[
                    ("processed_echos", (&all_echos_to_finalize).into()),
                    ("original_message", (&original_message).into()),
                ],
            )
            .with_dependency(&finalize_trigger)
            .with_dependency(&ready_sent);

            Ok(output)
        } else {
            Ok(constant::<_, Option<T>>("output", None).with_dependency(all_shards_sent))
        }
    }
}
