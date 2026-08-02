use alloc::collections::BTreeSet;
use ayatori::{protocol_author_api::*, signature::rand_core::TryRng};

// ANCHOR: composable
#[derive(Debug)]
pub struct DistributedRng;

impl<SP: SessionParameters> ComposableProtocol<SP> for DistributedRng {
    // ANCHOR_END: composable

    // ANCHOR: composable-build-data
    type BuildData = ThresholdGroup<SP::Verifier>;
    // ANCHOR_END: composable-build-data

    // ANCHOR: composable-output-node
    type OutputNode = Node<ComputeScalar<SP>>;
    // ANCHOR_END: composable-output-node

    // ANCHOR: composable-signature
    fn signature() -> ProtocolSignature {
        ProtocolSignature::new().input("x").input("y")
    }
    // ANCHOR_END: composable-signature

    // ANCHOR: composable-build
    fn build(
        _party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        inputs: ArgNodes<SP>,
    ) -> Result<Self::OutputNode, RuntimeError> {
        // ANCHOR_END: composable-build

        // ANCHOR: build-inputs
        let threshold_parties = build_data;
        let all_parties = threshold_parties.ids();
        let x = inputs.get("x")?;
        let y = inputs.get("y")?;
        // ANCHOR_END: build-inputs

        // ANCHOR: build-b
        let my_b = compute_scalar_with_rng(
            "my_b",
            |rng, args| {
                let x = args.get::<u32>("x")?;
                Ok(rng.try_next_u32().unwrap() % x)
            },
            &[("x", x.into())],
        );
        // ANCHOR_END: build-b

        // ANCHOR: build-r
        let my_r = compute_scalar_with_rng(
            "my_r",
            |rng, args| {
                let y = args.get::<u32>("y")?;
                Ok(rng.try_next_u32().unwrap() % y)
            },
            &[("y", y.into())],
        );
        // ANCHOR_END: build-r

        // ANCHOR: build-c
        let my_c = compute_scalar(
            "my_c",
            |args| {
                let b = args.get::<u32>("b")?;
                let r = args.get::<u32>("r")?;
                Ok(b + r)
            },
            &[("b", (&my_b).into()), ("r", (&my_r).into())],
        );
        // ANCHOR_END: build-c

        // ANCHOR: build-send-c
        let (message_c_out, message_c_in) = broadcast_message::<_, u32>("c");
        let c_broadcasted = message_c_out.send(&my_c, all_parties);
        let c = message_c_in.receive();
        // ANCHOR_END: build-send-c

        // ANCHOR: build-collect-c
        let all_c = collect(&c, threshold_parties).with_dependency(&c_broadcasted);
        // ANCHOR_END: build-collect-c

        // ANCHOR: build-send-b-r
        let (message_b_out, message_b_in) = broadcast_message::<_, u32>("b");
        let b_broadcasted = message_b_out
            .send(&my_b, all_parties)
            .with_dependency(&all_c);
        let b = message_b_in.receive();

        let (message_r_out, message_r_in) = broadcast_message::<_, u32>("r");
        let r_broadcasted = message_r_out
            .send(&my_r, all_parties)
            .with_dependency(&all_c);
        let r = message_r_in.receive();
        // ANCHOR_END: build-send-b-r

        // ANCHOR: build-check-commitment
        let commitment_correct = compute_mapping_sender_fallible(
            "commitment_correct",
            |id, args| {
                // TODO (#9): since we're sending a message to ourself too,
                // we can skip the verification in the message is ours.
                if id == args.my_id() {
                    return Ok(());
                }
                let b = args.get::<u32>("b")?;
                let r = args.get::<u32>("r")?;
                let c = args.get::<u32>("c")?;
                if b + r == *c {
                    Ok(())
                } else {
                    Err(SenderError::new("b + r != c").into())
                }
            },
            &[("c", (&c).into()), ("b", (&b).into()), ("r", (&r).into())],
        );
        // ANCHOR_END: build-check-commitment

        // ANCHOR: build-finalize
        let all_commitments_correct = collect(&commitment_correct, threshold_parties)
            .with_dependency(&b_broadcasted)
            .with_dependency(&r_broadcasted);
        let all_b = collect(&b, threshold_parties);
        let output = compute_scalar(
            "output",
            |args| {
                let bs = args.get_map::<u32>("b")?;
                let x = args.get::<u32>("x")?;
                Ok(bs.values().copied().sum::<u32>() % x)
            },
            &[("b", (&all_b).into()), ("x", x.into())],
        )
        .with_dependency(&all_commitments_correct);
        Ok(output)
        // ANCHOR_END: build-finalize
    }
}

// ANCHOR: executable-private-data
impl<SP: SessionParameters> ExecutableProtocol<SP> for DistributedRng {
    type PrivateData = u32;

    fn make_private_inputs(private_data: &Self::PrivateData) -> PrivateInputs {
        PrivateInputs::new().input("y", *private_data)
    }
    // ANCHOR_END: executable-private-data

    // ANCHOR: executable-shared-data
    type SharedData = (u32, ThresholdGroup<SP::Verifier>);

    fn make_public_inputs(shared_data: &Self::SharedData) -> PublicInputs {
        PublicInputs::new().input("x", shared_data.0)
    }
    // ANCHOR_END: executable-shared-data

    // ANCHOR: executable-build-data
    fn make_build_data(shared_data: &Self::SharedData) -> Self::BuildData {
        shared_data.1.clone()
    }
    // ANCHOR_END: executable-build-data

    // ANCHOR: executable-participants
    fn all_participants(shared_data: &Self::SharedData) -> BTreeSet<SP::Verifier> {
        shared_data.1.ids().clone()
    }
    // ANCHOR_END: executable-participants

    // ANCHOR: executable-output
    type Output = u32;
    // ANCHOR_END: executable-output
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use rand_chacha::ChaCha8Rng;

    use ayatori::{
        dev::{
            BinaryFormat, Replacement, TestSessionParams, TestSigner,
            run_sessions_sync,
        },
        protocol_user_api::*,
        signature::{Keypair, rand_core::SeedableRng},
    };

    use super::DistributedRng;

    // ANCHOR: happy_path
    type SP = TestSessionParams<BinaryFormat, ChaCha8Rng>;
    type P = DistributedRng;
    type S = Session<SP, P>;

    #[test]
    fn happy_path() {
        let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers
            .iter()
            .map(Keypair::verifying_key)
            .collect::<Vec<_>>();

        let private_data = 999;
        let shared_data = (1001, ThresholdGroup::new(&ids.iter().cloned().collect()));

        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let session_id = SessionId::random(&mut rng).unwrap();

        let sessions = signers
            .into_iter()
            .map(|signer| {
                S::new(session_id.clone(), signer, &private_data, &shared_data)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let results = run_sessions_sync(&mut rng, sessions).unwrap();

        let value = results.reports[&ids[0]].success_ref().unwrap();
        assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
        assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
    }
    // ANCHOR_END: happy_path

    #[test]
    fn provable_error() {
        let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers
            .iter()
            .map(Keypair::verifying_key)
            .collect::<Vec<_>>();

        let private_data = 999;
        let shared_data = (1001, ThresholdGroup::new(&ids.iter().cloned().collect()));

        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let session_id = SessionId::random(&mut rng).unwrap();

        // ANCHOR: replace_node
        let sessions = signers
            .into_iter()
            .enumerate()
            .map(|(idx, signer)| {
                if idx == 0 {
                    let replacement = Replacement::<SP>::compute_scalar(
                        &["my_c"],
                        |orig_value: &u32, _args| Ok(*orig_value + 1),
                    )
                    .unwrap();
                    S::new_with_replacements(
                        session_id.clone(),
                        signer,
                        &private_data,
                        &shared_data,
                        &[&replacement],
                    )
                    .unwrap()
                } else {
                    S::new(session_id.clone(), signer, &private_data, &shared_data)
                        .unwrap()
                }
            })
            .collect::<Vec<_>>();
        // ANCHOR_END: replace_node

        let results = run_sessions_sync(&mut rng, sessions).unwrap();

        let report1 = &results.reports[&ids[0]];
        assert!(report1.success_ref().is_some());
        assert!(report1.provable_errors.is_empty());

        // ANCHOR: test_report
        let report2 = &results.reports[&ids[1]];
        assert!(matches!(report2.outcome, SessionOutcome::Unfinishable(..)));
        let evidence = &report2.provable_errors[&ids[0]];
        assert!(
            evidence
                .description()
                .ends_with("and party TestVerifier(1): Sender error: b + r != c")
        );
        assert!(evidence.verify(&shared_data).is_ok());
        // ANCHOR_END: test_report

        let report3 = &results.reports[&ids[1]];
        assert!(matches!(report3.outcome, SessionOutcome::Unfinishable(..)));
        let evidence = &report3.provable_errors[&ids[0]];
        assert!(
            evidence
                .description()
                .ends_with("and party TestVerifier(1): Sender error: b + r != c")
        );
        assert!(evidence.verify(&shared_data).is_ok());
    }
}
