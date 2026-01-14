use ayatori::dev::TestPartyId;
use ayatori::protocol::*;

#[derive(Debug)]
struct DistributedRNG;

struct DistributedRNGShared<Id> {
    parties: Vec<Id>,
}

fn gen_x<Id>(_shared_data: &DistributedRNGShared<Id>, _args: &Args<Id>) -> u64 {
    1
}

fn gen_output<Id: PartyId>(_shared_data: &DistributedRNGShared<Id>, args: &Args<Id>) -> u64 {
    let xs = args.get_map::<u64>("x").unwrap();
    xs.values().sum()
}

impl<Id: PartyId> Protocol<Id> for DistributedRNG {
    type SharedData = DistributedRNGShared<Id>;
    type Output = u64;
    fn build(_my_id: &Id, shared_data: &Self::SharedData) -> Node<Id, Self> {
        let all_parties = PartyGroup::new(&shared_data.parties);
        let my_x = compute_scalar("my_x", gen_x, &[], &[]);
        let x_broadcasted = broadcast("x", &my_x, &all_parties, &[]);
        let x = receive("x", &all_parties);
        let all_x = collect("all_x", &x, &[&x_broadcasted]);
        compute_scalar("output", gen_output, &[&all_x], &[])
    }
}

#[test]
fn build_tree() {
    let ids = (1..4).map(TestPartyId::new).collect::<Vec<_>>();
    let shared_data = DistributedRNGShared { parties: ids.clone() };
    let output_node = DistributedRNG::build(&ids[0], &shared_data);
    println!("{:?}", output_node);

    let ruleset = Ruleset::new(output_node);
    println!("{:?}", ruleset);
    println!("{}", ruleset);
}
