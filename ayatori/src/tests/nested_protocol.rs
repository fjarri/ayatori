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
struct Protocol1;

#[derive(Debug, Clone)]
struct Protocol1SharedData<SP: SessionParameters> {
    p1: u64,
    party_group: PartyGroup<SP::Verifier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Protocol1Message(u64);

fn make_protocol1_value<SP: SessionParameters>(args: Args<SP>) -> Result<Protocol1Message, ComputeError> {
    let p1 = args.get::<u64>("p1")?;
    Ok(Protocol1Message(*p1))
}

fn make_protocol1_output<SP: SessionParameters>(args: Args<SP>) -> Result<u64, ComputeError> {
    let xs = args.get_map::<Protocol1Message>("x")?;
    Ok(xs.values().map(|message| message.0).sum())
}

impl<SP: SessionParameters> OuterProtocol<SP> for Protocol1 {
    type SharedData = Protocol1SharedData<SP>;
    type Output = u64;

    fn make_inputs(shared_data: &Self::SharedData) -> ProtocolArgs<SP> {
        ProtocolArgs::new().input("p1", shared_data.p1)
    }

    fn make_build_data(shared_data: &Self::SharedData) -> Self::BuildData {
        shared_data.party_group.clone()
    }
}

impl<SP: SessionParameters> InnerProtocol<SP> for Protocol1 {
    type BuildData = PartyGroup<SP::Verifier>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new().input("p1")
    }

    fn build(
        _my_id: &SP::Verifier,
        build_data: &Self::BuildData,
        inputs: ProtocolArgs<SP>,
    ) -> Result<Node<SP>, LocalError> {
        let message_x = ProtocolMessage::new::<Protocol1Message>("x");

        let all_parties = build_data;
        let p1 = inputs.get("p1")?;

        let my_x = compute_scalar("my_x", make_protocol1_value, &[&p1])?;
        let x_broadcasted = broadcast(&message_x, &my_x, all_parties)?;
        let x = receive(&message_x, all_parties);
        let all_x = collect(&x)?.with_dependencies(&[&x_broadcasted]);

        compute_scalar("output", make_protocol1_output, &[&all_x])
    }
}

#[test]
fn run_protocol() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
    let shared_data = Protocol1SharedData {
        p1: 1,
        party_group: PartyGroup::new(&ids),
    };

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let sessions = signers
        .into_iter()
        .map(|signer| Session::<TestSessionParams<BinaryFormat>, Protocol1>::new(signer, &shared_data).unwrap())
        .collect::<Vec<_>>();
    let _results = run_sessions_sync(&mut rng, sessions).unwrap();
}
