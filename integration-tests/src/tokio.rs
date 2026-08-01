#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ayatori::{
        dev::{
            BinaryFormat, TestSessionParams, TestSigner,
            tokio::{SessionRunner, run_sessions_async},
        },
        protocol_user_api::{
            BroadcastsSupported, DirectMessagesOnly, Session, SessionId, SessionRunnerConfiguration, ThresholdGroup,
            tokio::{par_run_session, run_session},
        },
        signature::{Keypair, rand_core::SeedableRng},
    };
    use rand_chacha::ChaCha8Rng;

    use crate::distributed_rng::TestProtocol;

    type SP = TestSessionParams<BinaryFormat, ChaCha8Rng>;
    type P = TestProtocol;

    async fn async_run<F, C>(f: F)
    where
        F: for<'a> SessionRunner<'a, SP, P, C>,
        C: SessionRunnerConfiguration<SP>,
    {
        let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();

        let shared_data = ThresholdGroup::new(&ids.iter().cloned().collect());

        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let session_id = SessionId::random(&mut rng).unwrap();

        let sessions = signers
            .into_iter()
            .map(|signer| Session::<SP, P>::new(session_id.clone(), signer, &(), &shared_data).unwrap())
            .collect::<Vec<_>>();

        let results = run_sessions_async::<SP, P, _, C>(&mut rng, sessions, f).await.unwrap();

        let value = results.reports[&ids[0]].success_ref().unwrap();
        assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
        assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
    }

    #[tokio::test]
    async fn run_dms_only() {
        async_run::<_, DirectMessagesOnly>(run_session::<SP, P, DirectMessagesOnly>).await;
    }

    #[tokio::test]
    async fn run_with_bcs() {
        async_run::<_, BroadcastsSupported>(run_session::<SP, P, BroadcastsSupported>).await;
    }

    #[tokio::test]
    async fn par_run() {
        async_run::<_, DirectMessagesOnly>(par_run_session::<SP, P, DirectMessagesOnly>).await;
    }
}
