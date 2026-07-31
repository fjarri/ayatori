use alloc::{collections::BTreeSet, string::String};

use ayatori::protocol_author_api::*;

#[derive(Debug)]
pub struct TestProtocol;

fn forking_computation<SP: SessionParameters>(_args: &Args<SP>) -> Result<OneOrBoth<u64, String>, UnattributableError> {
    Ok(OneOrBoth::Left(1))
}

fn merging_computation<SP: SessionParameters>(args: &Args<SP>) -> Result<u64, UnattributableError> {
    let one_or_both = args.get_merged::<u64, String>("x-or-y")?;
    if let OneOrBoth::Left(value) = one_or_both {
        Ok(*value)
    } else {
        Err(UnattributableError::runtime("Expected only the left value"))
    }
}

impl<SP: SessionParameters> ExecutableProtocol<SP> for TestProtocol {
    type PrivateData = ();
    type SharedData = ThresholdGroup<SP::Verifier>;
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
        shared_data.ids().clone()
    }
}

impl<SP: SessionParameters> ComposableProtocol<SP> for TestProtocol {
    type OutputNode = Node<ComputeScalar<SP>>;
    type BuildData = ThresholdGroup<SP::Verifier>;

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new()
    }

    fn build(
        _party_build_data: &PartyBuildData<SP>,
        _build_data: &Self::BuildData,
        _inputs: ArgNodes<SP>,
    ) -> Result<Self::OutputNode, RuntimeError> {
        let (my_x, my_y) = compute_forked_scalar("x-or-y", "my_x", "my_y", forking_computation, &[]);
        let merged = merge_scalars(&my_x, &my_y);
        let output = compute_scalar("output", merging_computation, &[("x-or-y", (&merged).into())]);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use rand_chacha::ChaCha8Rng;

    use ayatori::{
        dev::{BinaryFormat, TestSessionParams, TestSigner, run_sessions_sync},
        protocol_user_api::*,
        signature::{Keypair, rand_core::SeedableRng},
    };

    use super::TestProtocol;

    #[test]
    fn happy_path() {
        let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
        let party_group = ThresholdGroup::new(&ids.iter().cloned().collect());

        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let session_id = SessionId::random(&mut rng).unwrap();

        let sessions = signers
            .into_iter()
            .map(|signer| {
                Session::<TestSessionParams<BinaryFormat, ChaCha8Rng>, TestProtocol>::new(
                    session_id.clone(),
                    signer,
                    &(),
                    &party_group,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let results = run_sessions_sync(&mut rng, sessions).unwrap();

        assert_eq!(results.reports[&ids[0]].success_ref().unwrap(), &1);
        assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), &1);
        assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), &1);
    }
}
