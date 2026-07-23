#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ayatori::{
        dev::{
            BinaryFormat, TestSessionParams, TestSigner,
            tokio::{SessionRunner, run_sessions_async},
        },
        protocol_user_api::{
            Session, SessionId, ThresholdGroup,
            tokio::{par_run_session, run_session},
        },
        signature::{Keypair, rand_core::SeedableRng},
    };
    use rand_chacha::ChaCha8Rng;

    use crate::distributed_rng::TestProtocol;

    type SP = TestSessionParams<BinaryFormat, ChaCha8Rng>;
    type P = TestProtocol;

    async fn async_run<F>(f: F)
    where
        F: for<'a> SessionRunner<'a, SP, P>,
    {
        let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(Keypair::verifying_key).collect::<Vec<_>>();

        let shared_data = ThresholdGroup::new(&ids);

        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let session_id = SessionId::random(&mut rng).unwrap();

        let sessions = signers
            .into_iter()
            .map(|signer| Session::<SP, P>::new(session_id.clone(), signer, &(), &shared_data).unwrap())
            .collect::<Vec<_>>();

        let results = run_sessions_async::<SP, P, _>(&mut rng, sessions, f).await.unwrap();

        let value = results.reports[&ids[0]].success_ref().unwrap();
        assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
        assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
    }

    #[tokio::test]
    async fn run() {
        async_run(run_session::<SP, P>).await;
    }

    #[tokio::test]
    async fn par_run() {
        async_run(par_run_session::<SP, P>).await;
    }
}
