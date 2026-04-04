use alloc::{collections::BTreeSet, vec::Vec};

use rand_chacha::ChaCha8Rng;
use signature::{Keypair, rand_core::SeedableRng};

use crate::{
    dev::{BinaryFormat, Replacement, TestSessionParams, TestSigner, run_sessions_sync},
    protocol_author_api::*,
    protocol_user_api::*,
};

#[derive(Debug)]
struct TestProtocol;

fn gen_value<SP: SessionParameters>(_args: &Args<SP>) -> Result<u64, UnattributableError> {
    Ok(1)
}

fn verify<SP: SessionParameters>(id: &SP::Verifier, args: &Args<SP>) -> Result<(), SenderAttributableError> {
    let x = args.get::<u64>("x")?;
    // TODO (#9): since we're sending a message to ourself too, we need to account for that.
    // When short-circuiting is implemented, this function won't be called at all if `id == args.my_id()`.
    if id == args.my_id() || *x == 1 {
        Ok(())
    } else {
        Err(SenderAttributableError::new("Invalid x"))
    }
}

fn gen_output<SP: SessionParameters>(args: &Args<SP>) -> Result<u64, UnattributableError> {
    let xs = args.get_map::<u64>("x")?;
    Ok(xs.values().copied().sum())
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

    fn signature() -> ProtocolSignature {
        ProtocolSignature::new()
    }

    fn build(
        _party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        _inputs: ArgNodes<SP>,
    ) -> Result<Node<SP>, RuntimeError> {
        let message_x = ProtocolMessage::new::<u64>("x");

        let all_parties = build_data;
        let my_x = compute_scalar("my_x", gen_value, &[])?;
        let x_broadcasted = broadcast(&message_x, &my_x, all_parties)?;
        let x = receive(&message_x)?;
        let x_correct = compute_mapping_sender_fallible("x_correct", verify, &[("x", &x)])?;
        let all_x_correct = collect(&x_correct, all_parties)?.with_dependencies(&[&x_broadcasted])?;
        let all_x = collect(&x, all_parties)?;
        compute_scalar("output", gen_output, &[("x", &all_x)])?.with_dependencies(&[&all_x_correct])
    }
}

type SP = TestSessionParams<BinaryFormat>;
type S = Session<SP, TestProtocol>;

#[test]
fn happy_path() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
    let party_group = PartyGroup::new(&ids);

    let mut rng = ChaCha8Rng::seed_from_u64(123);
    let session_id = SessionId::random(&mut rng);

    let sessions = signers
        .into_iter()
        .map(|signer| S::new(session_id.clone(), signer, &(), &party_group).unwrap())
        .collect::<Vec<_>>();
    let results = run_sessions_sync(&mut rng, sessions).unwrap();

    let value = results.reports[&ids[0]].success_ref().unwrap();
    assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
    assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
}

#[test]
fn provable_error() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();
    let party_group = PartyGroup::new(&ids);

    let mut rng = ChaCha8Rng::seed_from_u64(123);
    let session_id = SessionId::random(&mut rng);

    let sessions = signers
        .into_iter()
        .enumerate()
        .map(|(idx, signer)| {
            if idx == 0 {
                let replacement =
                    Replacement::<SP>::compute_scalar(&["my_x"], |_orig_value: &u64, _args: &Args<SP>| Ok(2)).unwrap();
                S::new_with_replacements(session_id.clone(), signer, &(), &party_group, &[&replacement]).unwrap()
            } else {
                S::new(session_id.clone(), signer, &(), &party_group).unwrap()
            }
        })
        .collect::<Vec<_>>();
    let results = run_sessions_sync(&mut rng, sessions).unwrap();

    assert_eq!(results.reports[&ids[0]].success_ref().unwrap(), &4);
    assert!(results.reports[&ids[0]].provable_errors.is_empty());

    assert!(results.reports[&ids[1]].is_unfinishable());
    assert!(results.reports[&ids[1]].provable_errors.contains_key(&ids[0]));
    assert!(
        results.reports[&ids[1]].provable_errors[&ids[0]]
            .verify(&party_group)
            .is_ok()
    );

    assert!(results.reports[&ids[2]].is_unfinishable());
    assert!(results.reports[&ids[2]].provable_errors.contains_key(&ids[0]));
    assert!(
        results.reports[&ids[2]].provable_errors[&ids[0]]
            .verify(&party_group)
            .is_ok()
    );
}
