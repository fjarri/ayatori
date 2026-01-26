use crate::{
    dev::{BinaryFormat, TestSessionParams, TestSigner, run_sessions_sync},
    protocol::*,
    session::*,
};
use alloc::vec::Vec;

use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use signature::{Keypair, rand_core::SeedableRng};

#[derive(Debug)]
struct TestProtocol;

#[derive(Debug, Clone)]
struct TestProtocolShared<SP: SessionParameters> {
    parties: Vec<SP::Verifier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message1<Id>(Id);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message2<Id>(Id, Id);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message3<Id>(Id, Id);

fn make_scalar_value<SP: SessionParameters>(
    _shared_data: &TestProtocolShared<SP>,
    args: Args<SP>,
) -> Message1<SP::Verifier> {
    Message1(args.my_id().clone())
}

fn make_array_elem<SP: SessionParameters>(
    id: &SP::Verifier,
    _shared_data: &TestProtocolShared<SP>,
    args: Args<SP>,
) -> Message2<SP::Verifier> {
    Message2(args.my_id().clone(), id.clone())
}

fn make_array_elem_sans_me<SP: SessionParameters>(
    id: &SP::Verifier,
    _shared_data: &TestProtocolShared<SP>,
    args: Args<SP>,
) -> Message3<SP::Verifier> {
    Message3(args.my_id().clone(), id.clone())
}

fn gen_output<SP: SessionParameters>(_shared_data: &TestProtocolShared<SP>, args: Args<SP>) {
    let xs = args.get_map::<Message1<SP::Verifier>>("x");
    for (id, x) in xs {
        assert_eq!(id, &x.0);
    }

    let ys = args.get_map::<Message2<SP::Verifier>>("y");
    for (id, y) in ys {
        assert_eq!(id, &y.0);
        assert_eq!(args.my_id(), &y.1);
    }

    let zs = args.get_map::<Message3<SP::Verifier>>("z");
    assert!(!zs.contains_key(args.my_id()));
    for (id, z) in zs {
        assert_eq!(id, &z.0);
        assert_eq!(args.my_id(), &z.1);
    }
}

impl<SP: SessionParameters> Protocol<SP> for TestProtocol {
    type SharedData = TestProtocolShared<SP>;
    type Output = ();
    fn build(my_id: &SP::Verifier, shared_data: &Self::SharedData) -> Node<SP, Self> {
        let message_x = ProtocolMessage::new::<Message1<SP::Verifier>>("x");
        let message_y = ProtocolMessage::new::<Message2<SP::Verifier>>("y");
        let message_z = ProtocolMessage::new::<Message3<SP::Verifier>>("z");

        let all_parties = PartyGroup::new(&shared_data.parties);

        let my_x = compute_scalar("my_x", make_scalar_value, &[]);
        let x_broadcasted = broadcast(&message_x, &my_x, &all_parties);
        let x = receive(&message_x, &all_parties);
        let all_x = collect(&x).with_dependencies(&[&x_broadcasted]);

        let my_y = compute_array("my_y", make_array_elem, &all_parties, &[]);
        let y_sent = send(&message_y, &my_y);
        let y = receive(&message_y, my_y.group().unwrap());
        let all_y = collect(&y).with_dependencies(&[&y_sent]);

        let my_z = compute_array("my_z", make_array_elem_sans_me, &all_parties.except(my_id), &[]);
        let z_sent = send(&message_z, &my_z);
        let z = receive(&message_z, my_z.group().unwrap());
        let all_z = collect(&z).with_dependencies(&[&z_sent]);

        compute_scalar("output", gen_output, &[&all_x, &all_y, &all_z])
    }
}

#[test]
fn run_messages_protocol() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(|signer| signer.verifying_key()).collect::<Vec<_>>();
    let shared_data = TestProtocolShared { parties: ids.clone() };

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let sessions = signers
        .into_iter()
        .map(|signer| Session::<TestSessionParams<BinaryFormat>, TestProtocol>::new(signer, shared_data.clone()))
        .collect::<Vec<_>>();
    let _results = run_sessions_sync(&mut rng, sessions);
}
