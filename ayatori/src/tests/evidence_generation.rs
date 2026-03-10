use crate::{
    dev::{BinaryFormat, Replacement, TestSessionParams, TestSigner, run_sessions_sync},
    protocol::*,
    session::*,
};
use alloc::{collections::BTreeSet, vec::Vec};

use rand_chacha::ChaCha8Rng;
use signature::{Keypair, rand_core::SeedableRng};

#[derive(Debug)]
struct TestProtocol;

fn gen_value<SP: SessionParameters>(_args: Args<SP>) -> Result<u64, LocalError> {
    Ok(1)
}

fn verify<SP: SessionParameters>(id: &SP::Verifier, args: Args<SP>) -> Result<(), SenderError> {
    let x = args.get::<u64>("x")?;
    // TODO (#9): since we're sending a message to ourself too, we need to account for that.
    // When short-circuiting is implemented, this function won't be called at all if `id == args.my_id()`.
    if id == args.my_id() || *x == 1 {
        Ok(())
    } else {
        Err(SenderError::new())
    }
}

fn gen_output<SP: SessionParameters>(args: Args<SP>) -> Result<u64, LocalError> {
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
        _my_id: &SP::Verifier,
        build_data: &Self::BuildData,
        _inputs: ArgNodes<SP>,
    ) -> Result<Node<SP>, LocalError> {
        let message_x = ProtocolMessage::new::<u64>("x");

        let all_parties = build_data;
        let my_x = compute_scalar("my_x", gen_value, &[])?;
        let x_broadcasted = broadcast(&message_x, &my_x, all_parties)?;
        let x = receive(&message_x, all_parties)?;
        let x_correct = compute_array_sender_fallible("x_correct", verify, all_parties, &[("x", &x)])?;
        let all_x_correct = collect(&x_correct)?.with_dependencies(&[&x_broadcasted]);
        let all_x = collect(&x)?;
        Ok(compute_scalar("output", gen_output, &[("x", &all_x)])?.with_dependencies(&[&all_x_correct]))
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

    let value = results.outputs[&ids[0]];
    assert_eq!(results.outputs[&ids[1]], value);
    assert_eq!(results.outputs[&ids[2]], value);
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
                let replacement = Replacement::<SP>::compute_scalar("my_x", |_orig_value: &u64, _args: Args<SP>| Ok(2));
                S::new_with_replacements(session_id.clone(), signer, &(), &party_group, replacement).unwrap()
            } else {
                S::new(session_id.clone(), signer, &(), &party_group).unwrap()
            }
        })
        .collect::<Vec<_>>();
    let results = run_sessions_sync(&mut rng, sessions).unwrap();

    assert_eq!(results.outputs[&ids[0]], 4);
    assert!(!results.outputs.contains_key(&ids[1]));
    assert!(!results.outputs.contains_key(&ids[2]));

    assert!(results.reports.contains_key(&ids[0]));
    assert!(results.reports[&ids[0]].provable_errors.is_empty());

    assert!(results.reports.contains_key(&ids[1]));
    assert!(results.reports[&ids[1]].provable_errors.contains_key(&ids[0]));
    assert!(
        results.reports[&ids[1]].provable_errors[&ids[0]]
            .verify(&party_group)
            .is_ok()
    );

    assert!(results.reports.contains_key(&ids[2]));
    assert!(results.reports[&ids[2]].provable_errors.contains_key(&ids[0]));
    assert!(
        results.reports[&ids[2]].provable_errors[&ids[0]]
            .verify(&party_group)
            .is_ok()
    );
}
