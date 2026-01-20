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

fn sample_value<Id: PartyId>(rng: &mut dyn CryptoRng, _shared_data: &DistributedRNGShared<Id>, _args: Args<Id>) -> u64 {
    rng.next_u32() as u64
}

fn sample_nonce<Id: PartyId>(rng: &mut dyn CryptoRng, _shared_data: &DistributedRNGShared<Id>, _args: Args<Id>) -> u64 {
    rng.next_u32() as u64
}

fn commit_to_value<Id: PartyId>(_shared_data: &DistributedRNGShared<Id>, args: Args<Id>) -> u64 {
    let b = args.get::<u64>("my_b");
    let r = args.get::<u64>("my_r");
    b + r
}

fn verify_commitment<Id: PartyId>(_id: &Id, _shared_data: &DistributedRNGShared<Id>, args: Args<Id>) {
    let b = args.get::<u64>("b");
    let r = args.get::<u64>("r");
    let c = args.get::<u64>("c");
    assert_eq!(b + r, c);
    // TODO (#5): errors
}

fn gen_output<Id: PartyId>(_shared_data: &DistributedRNGShared<Id>, args: Args<Id>) -> u64 {
    let bs = args.get_map::<u64>("b");
    bs.values().sum()
}

impl<Id: PartyId> Protocol<Id> for DistributedRNG {
    type SharedData = DistributedRNGShared<Id>;
    type Output = u64;
    fn build(_my_id: &Id, shared_data: &Self::SharedData) -> Node<Id, Self> {
        let all_parties = PartyGroup::new(&shared_data.parties);
        let my_b = compute_scalar_private("my_b", sample_value, &[]);
        let my_r = compute_scalar_private("my_r", sample_nonce, &[]);
        let my_c = compute_scalar("my_c", commit_to_value, &[&my_b, &my_r]);
        let c_broadcasted = broadcast("c", &my_c, &all_parties);
        let c = receive("c", &all_parties);
        let all_c = collect(&c).with_dependencies(&[&c_broadcasted]);
        let b_broadcasted = broadcast("b", &my_b, &all_parties).with_dependencies(&[&all_c]);
        let r_broadcasted = broadcast("r", &my_r, &all_parties).with_dependencies(&[&all_c]);
        let b = receive("b", &all_parties);
        let r = receive("r", &all_parties);
        let hash_correct = verify("hash_correct", verify_commitment, &[&c, &b, &r]);
        let all_hash_correct = collect(&hash_correct).with_dependencies(&[&b_broadcasted, &r_broadcasted]);
        let all_b = collect(&b).with_dependencies(&[&b_broadcasted]);
        compute_scalar("output", gen_output, &[&all_b]).with_dependencies(&[&all_hash_correct])
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
