use alloc::{collections::BTreeSet, vec::Vec};

use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use signature::{Keypair, rand_core::SeedableRng};

use crate::{
    dev::{BinaryFormat, TestSessionParams, TestSigner, run_sessions_sync},
    protocol_author_api::*,
    protocol_user_api::*,
};

#[derive(Debug)]
struct TestProtocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message1<Id>(Id);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message2<Id>(Id, Id);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message3<Id>(Id, Id);

fn make_scalar_value<SP: SessionParameters>(args: &Args<SP>) -> Result<Message1<SP::Verifier>, LocalError> {
    Ok(Message1(args.my_id().clone()))
}

fn make_mapping_elem<SP: SessionParameters>(
    id: &SP::Verifier,
    args: &Args<SP>,
) -> Result<Message2<SP::Verifier>, LocalError> {
    Ok(Message2(args.my_id().clone(), id.clone()))
}

fn make_mapping_elem_sans_me<SP: SessionParameters>(
    id: &SP::Verifier,
    args: &Args<SP>,
) -> Result<Message3<SP::Verifier>, LocalError> {
    Ok(Message3(args.my_id().clone(), id.clone()))
}

fn gen_output<SP: SessionParameters>(args: &Args<SP>) -> Result<(), LocalError> {
    let xs = args.get_map::<Message1<SP::Verifier>>("x")?;
    for (id, x) in xs {
        assert_eq!(id, &x.0);
    }

    let ys = args.get_map::<Message2<SP::Verifier>>("y")?;
    for (id, y) in ys {
        assert_eq!(id, &y.0);
        assert_eq!(args.my_id(), &y.1);
    }

    let zs = args.get_map::<Message3<SP::Verifier>>("z")?;
    assert!(!zs.contains_key(args.my_id()));
    for (id, z) in zs {
        assert_eq!(id, &z.0);
        assert_eq!(args.my_id(), &z.1);
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
        my_id: &SP::Verifier,
        build_data: &Self::BuildData,
        _inputs: ArgNodes<SP>,
    ) -> Result<Node<SP>, LocalError> {
        let message_x = ProtocolMessage::new::<Message1<SP::Verifier>>("x");
        let message_y = ProtocolMessage::new::<Message2<SP::Verifier>>("y");
        let message_z = ProtocolMessage::new::<Message3<SP::Verifier>>("z");

        let all_parties = build_data;

        let my_x = compute_scalar("my_x", make_scalar_value, &[])?;
        let x_broadcasted = broadcast(&message_x, &my_x, all_parties)?;
        let x = receive(&message_x, all_parties)?;
        let all_x = collect(&x)?.with_dependencies(&[&x_broadcasted])?;

        let my_y = compute_mapping("my_y", make_mapping_elem, all_parties, &[])?;
        let y_sent = send(&message_y, &my_y)?;
        let y = receive(&message_y, my_y.group().unwrap())?;
        let all_y = collect(&y)?.with_dependencies(&[&y_sent])?;

        let my_z = compute_mapping("my_z", make_mapping_elem_sans_me, &all_parties.except(my_id), &[])?;
        let z_sent = send(&message_z, &my_z)?;
        let z = receive(&message_z, my_z.group().unwrap())?;
        let all_z = collect(&z)?.with_dependencies(&[&z_sent])?;

        compute_scalar("output", gen_output, &[("x", &all_x), ("y", &all_y), ("z", &all_z)])
    }
}

#[test]
fn happy_path() {
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
