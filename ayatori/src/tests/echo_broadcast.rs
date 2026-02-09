use crate::{
    dev::{BinaryFormat, TestSessionParams, TestSigner, run_sessions_sync},
    protocol::*,
    session::*,
};
use alloc::{collections::BTreeMap, vec::Vec};

use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use signature::{Keypair, rand_core::SeedableRng};

#[derive(Debug)]
struct TestProtocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message1<Id>(Id);

fn make_scalar_value<SP: SessionParameters>(args: Args<SP>) -> Result<Message1<SP::Verifier>, ComputeError> {
    Ok(Message1(args.my_id().clone()))
}

fn repackage_signed_values<SP: SessionParameters>(
    args: Args<SP>,
) -> Result<BTreeMap<SP::Verifier, SignedValue<SP>>, ComputeError> {
    let values = args.get_map::<SignedValue<SP>>("x_signed")?;
    let cloned = values
        .iter()
        .map(|(id, value): (&&SP::Verifier, &&SignedValue<SP>)| ((*id).clone(), (*value).clone()))
        .collect();
    Ok(cloned)
}

fn verify_echos_correct<SP: SessionParameters>(_id: &SP::Verifier, args: Args<SP>) -> Result<(), ComputeError> {
    // The messages we sent
    let _sent_map = args.get::<BTreeMap<SP::Verifier, SignedValue<SP>>>("my_x")?;

    // Echos received from `id`
    let _echos_map = args.get::<BTreeMap<SP::Verifier, SignedValue<SP>>>("remote_x")?;

    // - check that all the parties are present in the `echos_map`
    // - check that the signatures are correct
    // - check that the payload and metadata is the same (except for the `destination` part, which will differ)

    Ok(())
}

fn gen_output<SP: SessionParameters>(args: Args<SP>) -> Result<(), ComputeError> {
    let xs = args.get_map::<Message1<SP::Verifier>>("x")?;
    for (id, x) in xs {
        assert_eq!(id, &x.0);
    }

    Ok(())
}

impl<SP: SessionParameters> ExecutableProtocol<SP> for TestProtocol {
    type SharedData = PartyGroup<SP::Verifier>;
    type Output = ();
    fn make_inputs(_shared_data: &Self::SharedData) -> ProtocolArgs<SP> {
        ProtocolArgs::new()
    }
    fn make_build_data(shared_data: &Self::SharedData) -> Self::BuildData {
        shared_data.clone()
    }
}

impl<SP: SessionParameters> ComposableProtocol<SP> for TestProtocol {
    type BuildData = PartyGroup<SP::Verifier>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new()
    }

    fn build(
        _my_id: &SP::Verifier,
        build_data: &Self::BuildData,
        _inputs: ProtocolArgs<SP>,
    ) -> Result<Node<SP>, LocalError> {
        let message_x = ProtocolMessage::new::<Message1<SP::Verifier>>("x");

        let all_parties = build_data;

        let my_x = compute_scalar("my_x", make_scalar_value, &[])?;
        let x_broadcasted = broadcast(&message_x, &my_x, all_parties)?;
        let x_signed = receive_signed(&message_x, all_parties);
        let x = deserialize_received(&x_signed)?;

        let message_echo_x = ProtocolMessage::new::<BTreeMap<SP::Verifier, SignedValue<SP>>>("echo_x");
        let my_all_x_signed = compute_scalar(
            "my_all_x_signed",
            repackage_signed_values,
            &[("x_signed", &collect(&x_signed)?)],
        )?;
        let all_x_signed_broadcasted = broadcast(&message_echo_x, &my_all_x_signed, all_parties)?;
        let all_x_signed = receive(&message_echo_x, all_parties)?;
        let echos_correct = verify(
            "echos_correct",
            verify_echos_correct,
            &[("my_x", &my_all_x_signed), ("remote_x", &all_x_signed)],
        )?;
        let all_echos_correct = collect(&echos_correct)?;

        let all_x = collect(&x)?.with_dependencies(&[&x_broadcasted, &all_x_signed_broadcasted, &all_echos_correct]);

        compute_scalar("output", gen_output, &[("x", &all_x)])
    }
}

#[test]
fn run_protocol() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
    let party_group = PartyGroup::new(&ids);

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let sessions = signers
        .into_iter()
        .map(|signer| Session::<TestSessionParams<BinaryFormat>, TestProtocol>::new(signer, &party_group).unwrap())
        .collect::<Vec<_>>();
    let _results = run_sessions_sync(&mut rng, sessions).unwrap();
}
