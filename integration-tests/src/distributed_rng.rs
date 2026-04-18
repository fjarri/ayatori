use alloc::collections::BTreeSet;

use signature::rand_core::CryptoRngCore;

use ayatori::protocol_author_api::*;

#[derive(Debug)]
pub struct TestProtocol;

fn sample_value<SP: SessionParameters>(
    rng: &mut dyn CryptoRngCore,
    _args: &Args<SP>,
) -> Result<u64, UnattributableError> {
    Ok(u64::from(rng.next_u32()))
}

fn sample_nonce<SP: SessionParameters>(
    rng: &mut dyn CryptoRngCore,
    _args: &Args<SP>,
) -> Result<u64, UnattributableError> {
    Ok(u64::from(rng.next_u32()))
}

fn commit_to_value<SP: SessionParameters>(args: &Args<SP>) -> Result<u64, UnattributableError> {
    let b = args.get::<u64>("b")?;
    let r = args.get::<u64>("r")?;
    Ok(b + r)
}

fn verify_commitment<SP: SessionParameters>(
    _id: &SP::Verifier,
    args: &Args<SP>,
) -> Result<(), SenderAttributableError> {
    let b = args.get::<u64>("b")?;
    let r = args.get::<u64>("r")?;
    let c = args.get::<u64>("c")?;
    if b + r == *c {
        Ok(())
    } else {
        Err(SenderAttributableError::new("b + r != c"))
    }
}

fn gen_output<SP: SessionParameters>(args: &Args<SP>) -> Result<u64, UnattributableError> {
    let bs = args.get_map::<u64>("b")?;
    Ok(bs.values().copied().sum())
}

impl<SP: SessionParameters> ExecutableProtocol<SP> for TestProtocol {
    type PrivateData = ();
    type SharedData = PartyGroup<SP::Verifier>;
    type Output = u64;

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
    type OutputNode = Node<ComputeScalar<SP>>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new()
    }

    fn build(
        _party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        _inputs: ArgNodes<SP>,
    ) -> Result<Self::OutputNode, RuntimeError> {
        let message_b = ProtocolMessage::new::<u64>("b");
        let message_r = ProtocolMessage::new::<u64>("r");
        let message_c = ProtocolMessage::new::<u64>("c");

        let all_parties = build_data;
        let my_b = compute_scalar_with_rng("my_b", sample_value, &[]);
        let my_r = compute_scalar_with_rng("my_r", sample_nonce, &[]);
        let my_c = compute_scalar("my_c", commit_to_value, &[("b", (&my_b).into()), ("r", (&my_r).into())]);
        let c_broadcasted = broadcast(&message_c, &my_c, all_parties);
        let c = receive(&message_c);
        let all_c = collect(&c, all_parties).with_dependency(&c_broadcasted);
        let b_broadcasted = broadcast(&message_b, &my_b, all_parties).with_dependency(&all_c);
        let r_broadcasted = broadcast(&message_r, &my_r, all_parties).with_dependency(&all_c);
        let b = receive(&message_b);
        let r = receive(&message_r);
        let hash_correct = compute_mapping_sender_fallible(
            "hash_correct",
            verify_commitment,
            &[("c", (&c).into()), ("b", (&b).into()), ("r", (&r).into())],
        );
        let all_hash_correct = collect(&hash_correct, all_parties)
            .with_dependency(&b_broadcasted)
            .with_dependency(&r_broadcasted);
        let all_b = collect(&b, all_parties).with_dependency(&b_broadcasted);
        Ok(compute_scalar("output", gen_output, &[("b", (&all_b).into())]).with_dependency(&all_hash_correct))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use rand_chacha::ChaCha8Rng;
    use signature::{Keypair, rand_core::SeedableRng};

    use ayatori::{
        dev::{BinaryFormat, TestSessionParams, TestSigner, run_sessions_sync},
        protocol_user_api::*,
    };

    use super::TestProtocol;

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
                Session::<TestSessionParams<BinaryFormat>, TestProtocol>::new(
                    session_id.clone(),
                    signer,
                    &(),
                    &party_group,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let results = run_sessions_sync(&mut rng, sessions).unwrap();

        let value = results.reports[&ids[0]].success_ref().unwrap();
        assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
        assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
    }
}
