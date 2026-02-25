use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use signature::{Keypair, rand_core::SeedableRng};

use crate::{
    dev::{BinaryFormat, TestSessionParams, TestSigner, run_sessions_sync},
    protocol::*,
    session::*,
};

fn prepare_echo_pack<SP: SessionParameters>(
    args: Args<SP>,
) -> Result<BTreeMap<SP::Verifier, SignedHash<SP>>, ComputeError<SP>> {
    let values = args.get_map::<VerifiedValue<SP>>("values_verified_map")?;
    let cloned = values
        .iter()
        .map(|(id, value)| value.to_signed_hash().map(|value| ((*id).clone(), value)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(cloned)
}

fn verify_echos_correct<SP: SessionParameters>(id: &SP::Verifier, args: Args<SP>) -> Result<(), ComputeError<SP>> {
    let all_ids = args.get::<BTreeSet<SP::Verifier>>("all_ids")?;

    // The messages we received from all nodes
    // Their validity (correct metadata and contents) is checked elsewhere,
    // so here we assumed they are correct.
    let received = args.get_map::<VerifiedValue<SP>>("received")?;

    // The echoed messages we received from `id`
    let echoed = args.get::<BTreeMap<SP::Verifier, SignedHash<SP>>>("echoed")?;

    // Check that all the parties are present in the `echos_map`
    let ids_received = echoed.keys().cloned().collect::<BTreeSet<_>>();
    if &ids_received != all_ids {
        return Err(ComputeError::sender());
    }

    // Check that the messages are correctly signed and have correct metadata
    for (from, message) in echoed.iter() {
        if from != message.source() {
            return Err(ComputeError::sender());
        }
        if id != message.metadata().destination() {
            return Err(ComputeError::sender());
        }

        let ethalon = received
            .get(from)
            .expect("we checked that the ID is present in the message map");

        if ethalon.metadata().full_name() != message.metadata().full_name() {
            return Err(ComputeError::sender());
        }

        if ethalon.metadata().session_id() != message.metadata().session_id() {
            return Err(ComputeError::sender());
        }

        if !message.is_signature_correct() {
            return Err(ComputeError::sender());
        }
    }

    // Check that the payload and metadata is the same (except for the `destination` part, which will differ)
    for (from, message) in echoed.iter() {
        let ethalon = received
            .get(from)
            .expect("we checked that the ID is present in the message map");

        if !ethalon.payload_hash_matches(message)? {
            let associated_data = ((*ethalon).clone().unverify(), message);
            return Err(ComputeError::third_party(from, associated_data)?);
        }
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
        _my_id: &SP::Verifier,
        build_data: &Self::BuildData,
        inputs: ProtocolArgs<SP>,
    ) -> Result<Node<SP>, LocalError> {
        let (message, all_parties) = build_data;
        let my_value = inputs.get("value")?;

        let value_broadcasted = broadcast(message, my_value, all_parties)?;
        let values_verified = receive_signed(message, all_parties);
        let values = deserialize_received(&values_verified)?;

        let message_echo = ProtocolMessage::new::<BTreeMap<SP::Verifier, SignedHash<SP>>>("echo");
        let all_values_verified = collect(&values_verified)?;
        let all_values_deserialized = collect(&values)?;

        let my_echo_pack_sendable = compute_scalar(
            "my_echo_pack_signed",
            prepare_echo_pack,
            &[("values_verified_map", &all_values_verified)],
        )?
        // We don't want to send out values that proved to be incorrect during deserialization checks.
        .with_dependencies(&[&all_values_deserialized]);

        let echo_pack_broadcasted = broadcast(&message_echo, &my_echo_pack_sendable, all_parties)?;
        let echo_pack = receive(&message_echo, all_parties)?;

        let all_ids = constant("all_ids", all_parties.ids().cloned().collect::<BTreeSet<_>>());
        let echos_correct = verify(
            "echos_correct",
            verify_echos_correct,
            &[
                ("all_ids", &all_ids),
                ("received", &all_values_verified),
                ("echoed", &echo_pack),
            ],
        )?;
        let all_echos_correct = collect(&echos_correct)?;
        let output = alias("output", &values).with_dependencies(&[
            &value_broadcasted,
            &all_echos_correct,
            &echo_pack_broadcasted,
        ]);

        Ok(output)
    }
}

#[derive(Debug)]
struct TestProtocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message1<Id>(Id);

fn make_scalar_value<SP: SessionParameters>(args: Args<SP>) -> Result<Message1<SP::Verifier>, ComputeError<SP>> {
    Ok(Message1(args.my_id().clone()))
}

fn gen_output<SP: SessionParameters>(args: Args<SP>) -> Result<(), ComputeError<SP>> {
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

    fn make_private_inputs(_private_data: &Self::PrivateData) -> PrivateInputs<SP> {
        PrivateInputs::new()
    }

    fn make_public_inputs(_shared_data: &Self::SharedData) -> PublicInputs<SP> {
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
        my_id: &SP::Verifier,
        build_data: &Self::BuildData,
        _inputs: ProtocolArgs<SP>,
    ) -> Result<Node<SP>, LocalError> {
        let message_x = ProtocolMessage::new::<Message1<SP::Verifier>>("x");

        let all_parties = build_data;

        let my_x = compute_scalar("my_x", make_scalar_value, &[])?;

        let x = call_protocol::<SP, EchoBroadcast>(
            "echo_x",
            my_id,
            &(message_x, all_parties.clone()),
            ProtocolArgs::new().input("value", &my_x),
        )?;

        let all_x = collect(&x)?;

        compute_scalar("output", gen_output, &[("x", &all_x)])
    }
}

#[test]
fn run_echo_protocol() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
    let party_group = PartyGroup::new(&ids);

    let mut rng = ChaCha8Rng::seed_from_u64(123);
    let session_id = SessionId::random(&mut rng);

    let sessions = signers
        .into_iter()
        .map(|signer| {
            Session::<TestSessionParams<BinaryFormat>, TestProtocol>::new(session_id.clone(), signer, &(), &party_group)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let _results = run_sessions_sync(&mut rng, sessions).unwrap();
}
