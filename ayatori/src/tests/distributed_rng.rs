use crate::{
    dev::{BinaryFormat, TestSessionParams, TestSigner, run_sessions_sync},
    protocol::*,
    session::*,
};
use alloc::vec::Vec;

use rand_chacha::ChaCha8Rng;
use signature::{
    Keypair,
    rand_core::{CryptoRngCore, SeedableRng},
};

#[derive(Debug)]
struct DistributedRNG;

fn sample_value<SP: SessionParameters>(rng: &mut dyn CryptoRngCore, _args: Args<SP>) -> Result<u64, ComputeError<SP>> {
    Ok(u64::from(rng.next_u32()))
}

fn sample_nonce<SP: SessionParameters>(rng: &mut dyn CryptoRngCore, _args: Args<SP>) -> Result<u64, ComputeError<SP>> {
    Ok(u64::from(rng.next_u32()))
}

fn commit_to_value<SP: SessionParameters>(args: Args<SP>) -> Result<u64, ComputeError<SP>> {
    let b = args.get::<u64>("b")?;
    let r = args.get::<u64>("r")?;
    Ok(b + r)
}

fn verify_commitment<SP: SessionParameters>(_id: &SP::Verifier, args: Args<SP>) -> Result<(), ComputeError<SP>> {
    let b = args.get::<u64>("b")?;
    let r = args.get::<u64>("r")?;
    let c = args.get::<u64>("c")?;
    if b + r == *c {
        Ok(())
    } else {
        Err(ComputeError::sender())
    }
}

fn gen_output<SP: SessionParameters>(args: Args<SP>) -> Result<u64, ComputeError<SP>> {
    let bs = args.get_map::<u64>("b")?;
    Ok(bs.values().copied().sum())
}

impl<SP: SessionParameters> ExecutableProtocol<SP> for DistributedRNG {
    type SharedData = PartyGroup<SP::Verifier>;
    type Output = u64;

    fn make_inputs(_shared_data: &Self::SharedData) -> ProtocolArgs<SP> {
        ProtocolArgs::new()
    }

    fn make_build_data(shared_data: &Self::SharedData) -> Self::BuildData {
        shared_data.clone()
    }
}

impl<SP: SessionParameters> ComposableProtocol<SP> for DistributedRNG {
    type BuildData = PartyGroup<SP::Verifier>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new()
    }

    fn build(
        _my_id: &SP::Verifier,
        build_data: &Self::BuildData,
        _inputs: ProtocolArgs<SP>,
    ) -> Result<Node<SP>, LocalError> {
        let message_b = ProtocolMessage::new::<u64>("b");
        let message_r = ProtocolMessage::new::<u64>("r");
        let message_c = ProtocolMessage::new::<u64>("c");

        let all_parties = build_data;
        let my_b = compute_scalar_private("my_b", sample_value, &[])?;
        let my_r = compute_scalar_private("my_r", sample_nonce, &[])?;
        let my_c = compute_scalar("my_c", commit_to_value, &[("b", &my_b), ("r", &my_r)])?;
        let c_broadcasted = broadcast(&message_c, &my_c, all_parties)?;
        let c = receive(&message_c, all_parties)?;
        let all_c = collect(&c)?.with_dependencies(&[&c_broadcasted]);
        let b_broadcasted = broadcast(&message_b, &my_b, all_parties)?.with_dependencies(&[&all_c]);
        let r_broadcasted = broadcast(&message_r, &my_r, all_parties)?.with_dependencies(&[&all_c]);
        let b = receive(&message_b, all_parties)?;
        let r = receive(&message_r, all_parties)?;
        let hash_correct = verify("hash_correct", verify_commitment, &[("c", &c), ("b", &b), ("r", &r)])?;
        let all_hash_correct = collect(&hash_correct)?.with_dependencies(&[&b_broadcasted, &r_broadcasted]);
        let all_b = collect(&b)?.with_dependencies(&[&b_broadcasted]);
        Ok(compute_scalar("output", gen_output, &[("b", &all_b)])?.with_dependencies(&[&all_hash_correct]))
    }
}

#[test]
fn run_protocol() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
    let party_group = PartyGroup::new(&ids);

    let mut rng = ChaCha8Rng::seed_from_u64(123);
    let session_id = SessionId::random(&mut rng);

    let sessions = signers
        .into_iter()
        .map(|signer| {
            Session::<TestSessionParams<BinaryFormat>, DistributedRNG>::new(session_id.clone(), signer, &party_group)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let results = run_sessions_sync(&mut rng, sessions).unwrap();

    let value = results[&ids[0]];
    assert_eq!(results[&ids[1]], value);
    assert_eq!(results[&ids[2]], value);
}
