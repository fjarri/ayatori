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

#[derive(Clone)]
#[derive_where::derive_where(Debug)]
struct DistributedRNGShared<SP: SessionParameters> {
    parties: Vec<SP::Verifier>,
}

fn sample_value<SP: SessionParameters>(
    rng: &mut dyn CryptoRngCore,
    _shared_data: &DistributedRNGShared<SP>,
    _args: Args<SP>,
) -> Result<u64, ComputeError> {
    Ok(u64::from(rng.next_u32()))
}

fn sample_nonce<SP: SessionParameters>(
    rng: &mut dyn CryptoRngCore,
    _shared_data: &DistributedRNGShared<SP>,
    _args: Args<SP>,
) -> Result<u64, ComputeError> {
    Ok(u64::from(rng.next_u32()))
}

fn commit_to_value<SP: SessionParameters>(
    _shared_data: &DistributedRNGShared<SP>,
    args: Args<SP>,
) -> Result<u64, ComputeError> {
    let b = args.get::<u64>("my_b")?;
    let r = args.get::<u64>("my_r")?;
    Ok(b + r)
}

fn verify_commitment<SP: SessionParameters>(
    _id: &SP::Verifier,
    _shared_data: &DistributedRNGShared<SP>,
    args: Args<SP>,
) -> Result<(), ComputeError> {
    let b = args.get::<u64>("b")?;
    let r = args.get::<u64>("r")?;
    let c = args.get::<u64>("c")?;
    if b + r == *c { Ok(()) } else { Err(ComputeError::Data) }
}

fn gen_output<SP: SessionParameters>(
    _shared_data: &DistributedRNGShared<SP>,
    args: Args<SP>,
) -> Result<u64, ComputeError> {
    let bs = args.get_map::<u64>("b")?;
    Ok(bs.values().copied().sum())
}

impl<SP: SessionParameters> Protocol<SP> for DistributedRNG {
    type SharedData = DistributedRNGShared<SP>;
    type Output = u64;
    fn build(_my_id: &SP::Verifier, shared_data: &Self::SharedData) -> Result<Node<SP, Self>, LocalError> {
        let message_b = ProtocolMessage::new::<u64>("b");
        let message_r = ProtocolMessage::new::<u64>("r");
        let message_c = ProtocolMessage::new::<u64>("c");

        let all_parties = PartyGroup::new(&shared_data.parties);
        let my_b = compute_scalar_private("my_b", sample_value, &[])?;
        let my_r = compute_scalar_private("my_r", sample_nonce, &[])?;
        let my_c = compute_scalar("my_c", commit_to_value, &[&my_b, &my_r])?;
        let c_broadcasted = broadcast(&message_c, &my_c, &all_parties)?;
        let c = receive(&message_c, &all_parties);
        let all_c = collect(&c)?.with_dependencies(&[&c_broadcasted]);
        let b_broadcasted = broadcast(&message_b, &my_b, &all_parties)?.with_dependencies(&[&all_c]);
        let r_broadcasted = broadcast(&message_r, &my_r, &all_parties)?.with_dependencies(&[&all_c]);
        let b = receive(&message_b, &all_parties);
        let r = receive(&message_r, &all_parties);
        let hash_correct = verify("hash_correct", verify_commitment, &[&c, &b, &r])?;
        let all_hash_correct = collect(&hash_correct)?.with_dependencies(&[&b_broadcasted, &r_broadcasted]);
        let all_b = collect(&b)?.with_dependencies(&[&b_broadcasted]);
        Ok(compute_scalar("output", gen_output, &[&all_b])?.with_dependencies(&[&all_hash_correct]))
    }
}

#[test]
fn run_protocol() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
    let shared_data = DistributedRNGShared { parties: ids.clone() };

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let sessions = signers
        .into_iter()
        .map(|signer| {
            Session::<TestSessionParams<BinaryFormat>, DistributedRNG>::new(signer, shared_data.clone()).unwrap()
        })
        .collect::<Vec<_>>();
    let results = run_sessions_sync(&mut rng, sessions).unwrap();

    let value = results[&ids[0]];
    assert_eq!(results[&ids[1]], value);
    assert_eq!(results[&ids[2]], value);
}
