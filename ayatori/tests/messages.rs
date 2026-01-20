use ayatori::dev::{TestPartyId, run_sessions_sync};
use ayatori::protocol::*;
use ayatori::session::*;

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

#[derive(Debug)]
struct TestProtocol;

#[derive(Clone)]
struct TestProtocolShared<Id> {
    parties: Vec<Id>,
}

#[derive(Clone)]
struct Message1<Id>(Id);

#[derive(Clone)]
struct Message2<Id>(Id, Id);

#[derive(Clone)]
struct Message3<Id>(Id, Id);

fn make_scalar_value<Id: PartyId>(_shared_data: &TestProtocolShared<Id>, args: Args<Id>) -> Message1<Id> {
    Message1(args.my_id().clone())
}

fn make_array_elem<Id: PartyId>(id: &Id, _shared_data: &TestProtocolShared<Id>, args: Args<Id>) -> Message2<Id> {
    Message2(args.my_id().clone(), id.clone())
}

fn make_array_elem_sans_me<Id: PartyId>(
    id: &Id,
    _shared_data: &TestProtocolShared<Id>,
    args: Args<Id>,
) -> Message3<Id> {
    Message3(args.my_id().clone(), id.clone())
}

fn gen_output<Id: PartyId>(_shared_data: &TestProtocolShared<Id>, args: Args<Id>) {
    let xs = args.get_map::<Message1<Id>>("all_x");
    for (id, x) in xs {
        assert_eq!(id, x.0);
    }

    let ys = args.get_map::<Message2<Id>>("all_y");
    for (id, y) in ys {
        assert_eq!(id, y.0);
        assert_eq!(args.my_id(), &y.1);
    }

    let zs = args.get_map::<Message3<Id>>("all_z");
    assert!(!zs.contains_key(args.my_id()));
    for (id, z) in zs {
        assert_eq!(id, z.0);
        assert_eq!(args.my_id(), &z.1);
    }
}

impl<Id: PartyId> Protocol<Id> for TestProtocol {
    type SharedData = TestProtocolShared<Id>;
    type Output = ();
    fn build(my_id: &Id, shared_data: &Self::SharedData) -> Node<Id, Self> {
        let all_parties = PartyGroup::new(&shared_data.parties);

        let my_x = compute_scalar("my_x", make_scalar_value, &[]);
        let x_broadcasted = broadcast("x", &my_x, &all_parties);
        let x = receive("x", &all_parties);
        let all_x = collect("all_x", &x, &[&x_broadcasted]);

        let my_y = compute_array("my_y", make_array_elem, &all_parties, &[]);
        let y_sent = send("y", &my_y);
        let y = receive("y", my_y.group().unwrap());
        let all_y = collect("all_y", &y, &[&y_sent]);

        let my_z = compute_array("my_z", make_array_elem_sans_me, &all_parties.except(my_id), &[]);
        let z_sent = send("z", &my_z);
        let z = receive("z", my_z.group().unwrap());
        let all_z = collect("all_z", &z, &[&z_sent]);

        compute_scalar("output", gen_output, &[&all_x, &all_y, &all_z])
    }
}

#[test]
fn run_messages_protocol() {
    let ids = (1..4).map(TestPartyId::new).collect::<Vec<_>>();
    let shared_data = TestProtocolShared { parties: ids.clone() };

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let sessions = ids
        .iter()
        .map(|id| Session::<_, TestProtocol>::new(id, shared_data.clone()))
        .collect::<Vec<_>>();
    let _results = run_sessions_sync(&mut rng, sessions);
}
