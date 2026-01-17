use ayatori::dev::{TestPartyId, run_sessions_sync};
use ayatori::protocol::*;
use ayatori::session::*;

use rand_chacha::ChaCha8Rng;
use rand_core::{CryptoRng, SeedableRng};

#[derive(Debug)]
struct DistributedRNG;

#[derive(Clone)]
struct DistributedRNGShared<Id> {
    parties: Vec<Id>,
}

fn gen_x<Id>(rng: &mut dyn CryptoRng, _shared_data: &DistributedRNGShared<Id>, _args: Args) -> u64 {
    rng.next_u32() as u64
}

fn gen_output<Id: PartyId>(_shared_data: &DistributedRNGShared<Id>, args: Args) -> u64 {
    let xs = args.get_map::<Id, u64>("all_x");
    xs.values().sum()
}

impl<Id: PartyId> Protocol<Id> for DistributedRNG {
    type SharedData = DistributedRNGShared<Id>;
    type Output = u64;
    fn build(_my_id: &Id, shared_data: &Self::SharedData) -> Node<Id, Self> {
        let all_parties = PartyGroup::new(&shared_data.parties);
        let my_x = compute_scalar_private("my_x", gen_x, &[], &[]);
        let x_broadcasted = broadcast("x", &my_x, &all_parties, &[]);
        let x = receive("x", &all_parties);
        let all_x = collect("all_x", &x, &[&x_broadcasted]);
        compute_scalar("output", gen_output, &[&all_x], &[])
    }
}

#[test]
fn run_protocol() {
    let ids = (1..4).map(TestPartyId::new).collect::<Vec<_>>();
    let shared_data = DistributedRNGShared { parties: ids.clone() };

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let sessions = ids
        .iter()
        .map(|id| Session::<_, DistributedRNG>::new(id, shared_data.clone()))
        .collect::<Vec<_>>();
    let results = run_sessions_sync(&mut rng, sessions);

    let value = results[&ids[0]];
    assert_eq!(results[&ids[1]], value);
    assert_eq!(results[&ids[2]], value);
}
