use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use signature::{
    Keypair,
    rand_core::{CryptoRngCore, SeedableRng},
};

use crate::{
    dev::{BinaryFormat, Replacement, TestSessionParams, TestSigner, run_sessions_sync},
    protocol_author_api::*,
    protocol_user_api::*,
};

fn prepare_echo_pack<SP: SessionParameters>(
    args: &Args<SP>,
) -> Result<BTreeMap<SP::Verifier, SignedHash<SP>>, LocalError> {
    let values = args.get_map::<VerifiedValue<SP>>("values_verified_map")?;
    let cloned = values
        .iter()
        // Don't send out our own message the second time
        .filter(|(id, _value)| id != &&args.my_id())
        .map(|(id, value)| value.to_signed_hash().map(|value| ((*id).clone(), value)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(cloned)
}

fn verify_echo_pack_correct<SP: SessionParameters>(id: &SP::Verifier, args: &Args<SP>) -> Result<(), SenderError> {
    let all_ids = args.get::<BTreeSet<SP::Verifier>>("all_ids")?;

    // The messages we received from all nodes
    // Their validity (correct metadata and contents) is checked elsewhere,
    // so here we assumed they are correct.
    let received = args.get_map::<VerifiedValue<SP>>("received")?;

    // The echoed messages we received from `id`
    let echoed = args.get::<BTreeMap<SP::Verifier, SignedHash<SP>>>("echoed")?;

    // Check that all the parties are present in the `echos_map`
    // (except for the sender, who intentionally didn't resend their original message).
    let ids_received = echoed.keys().cloned().collect::<BTreeSet<_>>();
    let mut all_ids_except_for_sender = all_ids.clone();
    all_ids_except_for_sender.remove(id);
    if ids_received != all_ids_except_for_sender {
        return Err(SenderError::new());
    }

    // Check that the messages are correctly signed and have correct metadata
    for (from, message) in echoed.iter() {
        if from != message.source() {
            return Err(SenderError::new());
        }
        if id != message.metadata().destination() {
            return Err(SenderError::new());
        }

        let ethalon = received
            .get(from)
            .expect("we checked that the ID is present in the message map");

        if ethalon.metadata().full_name() != message.metadata().full_name() {
            return Err(SenderError::new());
        }

        if ethalon.metadata().session_id() != message.metadata().session_id() {
            return Err(SenderError::new());
        }

        if !message.is_signature_correct() {
            return Err(SenderError::new());
        }
    }

    Ok(())
}

fn verify_echo_contents<SP: SessionParameters>(id: &SP::Verifier, args: &Args<SP>) -> Result<(), ThirdPartyError<SP>> {
    // TODO (#9): since we're sending a message to ourself too, we need to account for that.
    // When short-circuiting is implemented, this function won't be called at all if `id == args.my_id()`.
    if id == args.my_id() {
        return Ok(());
    }

    // The messages we received from all nodes
    // Their validity (correct metadata and contents) is checked elsewhere,
    // so here we assumed they are correct.
    let received = args.get_map::<VerifiedValue<SP>>("received")?;

    // The echoed messages we received from `id`
    let echoed = args.get::<BTreeMap<SP::Verifier, SignedHash<SP>>>("echoed")?;

    // Check that the payload and metadata is the same (except for the `destination` part, which will differ)
    for (from, message) in echoed.iter() {
        let ethalon = received
            .get(from)
            .expect("we checked that the ID is present in the message map");

        if !ethalon.payload_hash_matches(message)? {
            let associated_data = ((*ethalon).clone().unverify(), message.clone());
            return Err(ThirdPartyError::new(from, associated_data)?);
        }
    }

    Ok(())
}

fn verify_echo_contents_error<SP: SessionParameters>(
    session_id: &SessionId<SP>,
    _guilty_party: &SP::Verifier,
    associated_data: &AssociatedData<SP>,
) -> Result<(), EvidenceError> {
    let (message1, message2) = associated_data.deserialize::<(SignedValue<SP>, SignedValue<SP>)>()?;

    if message1.metadata().session_id() != session_id {
        return Err(EvidenceError::new("Session ID mismatch"));
    }

    if message2.metadata().session_id() != session_id {
        return Err(EvidenceError::new("Session ID mismatch"));
    }

    Ok(())
}

#[derive(Debug)]
struct EchoBroadcast;

impl<SP: SessionParameters> ComposableProtocol<SP> for EchoBroadcast {
    type BuildData = (ProtocolMessage<SP>, PartyGroup<SP::Verifier>);

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new().input("value")
    }

    fn build(
        _party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        inputs: ArgNodes<SP>,
    ) -> Result<Node<SP>, LocalError> {
        let (message, all_parties) = build_data;
        let my_value = inputs.get("value")?;

        let value_broadcasted = broadcast(message, my_value, all_parties)?;
        let (values_verified, values) = receive_split(message)?;

        let message_echo = ProtocolMessage::new::<BTreeMap<SP::Verifier, SignedHash<SP>>>("echo");
        let all_values_verified = collect(&values_verified, all_parties)?;
        let all_values_deserialized = collect(&values, all_parties)?;

        let my_echo_pack_sendable = compute_scalar(
            "my_echo_pack_signed",
            prepare_echo_pack,
            &[("values_verified_map", &all_values_verified)],
        )?
        // We don't want to send out values that proved to be incorrect during deserialization checks.
        .with_dependencies(&[&all_values_deserialized])?;

        let echo_pack_broadcasted = broadcast(&message_echo, &my_echo_pack_sendable, all_parties)?;
        let echo_pack = receive(&message_echo)?;

        let all_ids = constant("all_ids", all_parties.ids().cloned().collect::<BTreeSet<_>>());
        let echo_packs_correct = compute_mapping_sender_fallible(
            "echo_packs_correct",
            verify_echo_pack_correct,
            &[
                ("all_ids", &all_ids),
                ("received", &all_values_verified),
                ("echoed", &echo_pack),
            ],
        )?;
        let echo_contents_correct = compute_mapping_third_party_fallible(
            "echo_contents_correct",
            verify_echo_contents,
            &[("received", &all_values_verified), ("echoed", &echo_pack)],
            verify_echo_contents_error,
        )?;

        let all_echo_packs_correct = collect(&echo_packs_correct, all_parties)?;
        let all_echo_contents_correct = collect(&echo_contents_correct, all_parties)?;
        let output = alias("output", &values).with_dependencies(&[
            &value_broadcasted,
            &all_echo_packs_correct,
            &all_echo_contents_correct,
            &echo_pack_broadcasted,
        ])?;

        Ok(output)
    }
}

#[derive(Debug)]
struct TestProtocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message1<Id>(Id);

fn make_scalar_value<SP: SessionParameters>(args: &Args<SP>) -> Result<Message1<SP::Verifier>, LocalError> {
    Ok(Message1(args.my_id().clone()))
}

fn gen_output<SP: SessionParameters>(args: &Args<SP>) -> Result<(), LocalError> {
    let xs = args.get_map::<Message1<SP::Verifier>>("x")?;
    for (id, x) in xs {
        assert_eq!(id, &x.0);
    }

    Ok(())
}

impl<SP: SessionParameters> ExecutableProtocol<SP> for TestProtocol {
    type PrivateData = ();
    type SharedData = PartyGroup<SP::Verifier>;
    type Output = ();

    fn make_private_inputs(_private_data: &Self::PrivateData) -> PrivateInputs {
        PrivateInputs::new()
    }

    fn make_public_inputs(_shared_data: &Self::SharedData) -> PublicInputs {
        PublicInputs::new()
    }

    fn make_build_data(shared_data: &Self::SharedData) -> Self::BuildData {
        shared_data.clone()
    }

    fn all_participants(shared_data: &Self::SharedData) -> BTreeSet<SP::Verifier> {
        shared_data.ids().cloned().collect()
    }
}

impl<SP: SessionParameters> ComposableProtocol<SP> for TestProtocol {
    type BuildData = PartyGroup<SP::Verifier>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new()
    }

    fn build(
        party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        _inputs: ArgNodes<SP>,
    ) -> Result<Node<SP>, LocalError> {
        let message_x = ProtocolMessage::new::<Message1<SP::Verifier>>("x");

        let all_parties = build_data;

        let my_x = compute_scalar("my_x", make_scalar_value, &[])?;

        let x = call_protocol::<SP, EchoBroadcast>(
            "echo_x",
            party_build_data,
            &(message_x, all_parties.clone()),
            ProtocolArgs::new().input("value", &my_x),
        )?;

        let all_x = collect(&x, all_parties)?;

        compute_scalar("output", gen_output, &[("x", &all_x)])
    }
}

type SP = TestSessionParams<BinaryFormat>;
type S = Session<SP, TestProtocol>;

#[test]
fn happy_path() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
    let party_group = PartyGroup::new(&ids);

    let mut rng = ChaCha8Rng::seed_from_u64(123);
    let session_id = SessionId::random(&mut rng);

    let sessions = signers
        .into_iter()
        .map(|signer| S::new(session_id.clone(), signer, &(), &party_group).unwrap())
        .collect::<Vec<_>>();
    let _results = run_sessions_sync(&mut rng, sessions).unwrap();
}

fn serialize_replacement(
    rng: &mut dyn CryptoRngCore,
    orig_value: &SignedValue<SP>,
    destination: &<SP as SessionParameters>::Verifier,
    args: &SerializeArgs<SP>,
) -> Result<SignedValue<SP>, LocalError> {
    if destination == &TestSigner::new(2).verifying_key() {
        let serialized_value = args.serde_adapter().serialize_typed(Message1(*destination))?;
        SignedValue::<SP>::new(
            rng,
            args.signer(),
            args.session_id(),
            args.message_name(),
            destination,
            serialized_value,
        )
    } else {
        Ok(orig_value.clone())
    }
}

fn dummy_verification(
    _orig_value: Result<&(), ThirdPartyError<SP>>,
    _id: &<SP as SessionParameters>::Verifier,
    _args: &Args<SP>,
) -> Result<(), ThirdPartyError<SP>> {
    Ok(())
}

#[test]
fn third_party_error() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
    let party_group = PartyGroup::new(&ids);

    let mut rng = ChaCha8Rng::seed_from_u64(123);
    let session_id = SessionId::random(&mut rng);

    let sessions = signers
        .into_iter()
        .enumerate()
        .map(|(idx, signer)| {
            if idx == 0 {
                let replacement1 = Replacement::<SP>::message(&["echo_x", "x"], serialize_replacement).unwrap();
                let replacement2 = Replacement::<SP>::compute_mapping_third_party_attributable(
                    &["echo_x", "echo_contents_correct"],
                    dummy_verification,
                )
                .unwrap();
                S::new_with_replacements(
                    session_id.clone(),
                    signer,
                    &(),
                    &party_group,
                    &[&replacement1, &replacement2],
                )
                .unwrap()
            } else {
                S::new(session_id.clone(), signer, &(), &party_group).unwrap()
            }
        })
        .collect::<Vec<_>>();
    let results = run_sessions_sync(&mut rng, sessions).unwrap();

    assert_eq!(results.reports[&ids[0]].success_ref().unwrap(), &());
    assert!(results.reports[&ids[0]].provable_errors.is_empty());

    assert!(results.reports[&ids[1]].is_unfinishable());
    assert!(results.reports[&ids[1]].provable_errors.contains_key(&ids[0]));
    assert!(
        results.reports[&ids[1]].provable_errors[&ids[0]]
            .verify(&party_group)
            .is_ok()
    );

    assert!(results.reports[&ids[2]].is_unfinishable());
    assert!(results.reports[&ids[2]].provable_errors.contains_key(&ids[0]));
    assert!(
        results.reports[&ids[2]].provable_errors[&ids[0]]
            .verify(&party_group)
            .is_ok()
    );
}
