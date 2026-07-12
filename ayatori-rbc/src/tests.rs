#![expect(clippy::indexing_slicing)]

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use rand_chacha::ChaCha8Rng;

use ayatori::{
    dev::{
        BinaryFormat, BlockMessagesRule, Replacement, RunSyncConfig, TestSessionParams, TestSigner, run_sessions_sync,
    },
    protocol_author_api::{Args, FullName, PrivateInputs, PublicInputs, UnattributableError},
    protocol_user_api::*,
    signature::{Keypair, rand_core::SeedableRng},
};

use crate::{
    BuildData, ReliableBroadcast,
    sharding::{Scheme, Shard, ShardKind},
};

type Value = u64;

#[derive(Debug, Clone, Copy)]
pub enum PrivateData {
    Sender { value: Value },
    Receiver,
}

// TODO: this implementation is only needed for tests
impl<SP: SessionParameters> ExecutableProtocol<SP> for ReliableBroadcast<Value> {
    type PrivateData = PrivateData;
    type SharedData = BuildData<SP>;
    type Output = Value;

    fn make_private_inputs(private_data: &Self::PrivateData) -> PrivateInputs {
        match private_data {
            PrivateData::Receiver => PrivateInputs::new(),
            PrivateData::Sender { value } => PrivateInputs::new().input("to_broadcast", *value),
        }
    }

    fn make_public_inputs(_shared_data: &Self::SharedData) -> PublicInputs {
        PublicInputs::new()
    }

    fn make_build_data(shared_data: &Self::SharedData) -> Self::BuildData {
        shared_data.clone()
    }

    fn all_participants(shared_data: &Self::SharedData) -> BTreeSet<SP::Verifier> {
        shared_data.all_parties().clone()
    }
}

type SP = TestSessionParams<BinaryFormat, ChaCha8Rng>;
type S = Session<SP, ReliableBroadcast<Value>>;

#[test]
fn happy_path() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();

    let build_data = BuildData::new(&ids.iter().copied().collect(), &ids[0], 1).unwrap();

    let mut rng = ChaCha8Rng::seed_from_u64(123);
    let session_id = SessionId::random(&mut rng).unwrap();

    let sessions = signers
        .into_iter()
        .map(|signer| {
            let private_data = if signer.verifying_key() == ids[0] {
                PrivateData::Sender { value: 111 }
            } else {
                PrivateData::Receiver
            };
            S::new(session_id.clone(), signer, &private_data, &build_data).unwrap()
        })
        .collect::<Vec<_>>();
    let results = run_sessions_sync(&mut rng, sessions).unwrap();

    let value = results.reports[&ids[0]].success_ref().unwrap();
    assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
    assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
}

#[test]
fn unresponsive_party() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();

    let build_data = BuildData::new(&ids.iter().copied().collect(), &ids[0], 1).unwrap();

    let mut rng = ChaCha8Rng::seed_from_u64(123);
    let session_id = SessionId::random(&mut rng).unwrap();

    let sessions = signers
        .into_iter()
        .map(|signer| {
            let private_data = if signer.verifying_key() == ids[0] {
                PrivateData::Sender { value: 111 }
            } else {
                PrivateData::Receiver
            };
            S::new(session_id.clone(), signer, &private_data, &build_data).unwrap()
        })
        .collect::<Vec<_>>();

    let runner = RunSyncConfig::default().block_messages(BlockMessagesRule {
        source: Some(ids[2]),
        name: Some(FullName::new_with_prefix(&["echo"]).unwrap()),
        destination: None,
    });

    let results = runner.run_sessions(&mut rng, sessions).unwrap();

    let value = results.reports[&ids[0]].success_ref().unwrap();
    assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
    assert!(matches!(
        results.reports[&ids[2]].outcome,
        SessionOutcome::Unfinishable(_)
    ));
}

#[expect(clippy::unnecessary_wraps)]
fn malicious_make_shards<SP: SessionParameters>(
    orig_value: &(Scheme, BTreeMap<SP::Verifier, Shard>),
    _args: &Args<SP>,
) -> Result<(Scheme, BTreeMap<SP::Verifier, Shard>), UnattributableError> {
    let (scheme, mut shards) = orig_value.clone();
    for shard in shards.values_mut() {
        if shard.kind() == ShardKind::Recovery {
            shard.data_mut().copy_from_slice(&[0xff, 0xff]);
            break;
        }
    }
    Ok((scheme, shards))
}

#[test]
fn sender_fault() {
    let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();

    let build_data = BuildData::new(&ids.iter().copied().collect(), &ids[0], 1).unwrap();

    let mut rng = ChaCha8Rng::seed_from_u64(123);
    let session_id = SessionId::random(&mut rng).unwrap();

    let sessions = signers
        .into_iter()
        .map(|signer| {
            if signer.verifying_key() == ids[0] {
                let private_data = PrivateData::Sender { value: 111 };
                let replacement =
                    Replacement::<SP>::compute_scalar(&["scheme_and_shards"], malicious_make_shards).unwrap();
                S::new_with_replacements(session_id.clone(), signer, &private_data, &build_data, &[&replacement])
                    .unwrap()
            } else {
                S::new(session_id.clone(), signer, &PrivateData::Receiver, &build_data).unwrap()
            }
        })
        .collect::<Vec<_>>();
    let results = run_sessions_sync(&mut rng, sessions).unwrap();

    for report in results.reports.values() {
        assert!(report.provable_errors.contains_key(&ids[0]));
        assert!(
            report.provable_errors[&ids[0]]
                .description()
                .ends_with("Third party attributable error: Merkle root mismatch")
        );
    }
}
