use signature::rand_core::CryptoRngCore;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ayatori::protocol_user_api::*;

// ANCHOR: signature
pub async fn run_session<SP, P>(
    rng: &mut impl CryptoRngCore,
    tx: &mpsc::Sender<Message<SP>>,
    rx: &mut mpsc::Receiver<Message<SP>>,
    cancellation: CancellationToken,
    mut session: Session<SP, P>,
) -> Result<SessionReport<SP, P>, UnattributableError>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    // ANCHOR_END: signature

    // ANCHOR: event_loop
    loop {
        while let Some(task) = session.make_task().unwrap() {
            let task_result = match task {
                // ANCHOR_END: event_loop

                // ANCHOR: task_compute
                Task::Compute(task) => {
                    let result = task.compute().unwrap();
                    session.add_result(result)
                }
                // ANCHOR_END: task_compute

                // ANCHOR: task_compute_rng
                Task::ComputeWithRng(task) => {
                    let result = task.compute(rng).unwrap();
                    session.add_result(result)
                }
                // ANCHOR_END: task_compute_rng

                // ANCHOR: task_send
                Task::Send(task) => {
                    let (message, result) = task.compute().unwrap();
                    tx.send(message).await.unwrap();
                    session.add_result(result)
                }
                // ANCHOR_END: task_send

                // ANCHOR: task_finalize_with_success
                Task::FinalizeWithSuccess(token) => {
                    return Ok(session.finalize_with_success(token).unwrap());
                }
                // ANCHOR_END: task_finalize_with_success

                // ANCHOR: task_finalize_with_stalled
                Task::FinalizeWithStalled(token) => {
                    return Ok(session.finalize_with_stalled(token));
                } // ANCHOR_END: task_finalize_with_stalled
            };

            // ANCHOR: task_result
            match task_result {
                Ok(()) => {}
                Err(TaskError::Unattributable(_error)) => panic!(),
                Err(TaskError::InvalidMessage(_error)) => panic!(),
                Err(TaskError::DuplicateMessages(_error)) => panic!(),
            }
            // ANCHOR_END: task_result
        }

        // ANCHOR: get_message
        let message_in = tokio::select! {
            message_in = rx.recv() => message_in.unwrap(),
            () = cancellation.cancelled() => return Ok(session.terminate()),
        };

        let message_id = MessageId::random(rng);
        session.add_message(&message_id, message_in);
        // ANCHOR_END: get_message
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ayatori::{
        dev::{BinaryFormat, TestSessionParams, TestSigner, run_async},
        protocol_user_api::*,
    };
    use rand_chacha::ChaCha8Rng;
    use signature::{Keypair, rand_core::SeedableRng};

    use super::run_session;
    use crate::distributed_rng::DistributedRng;

    type SP = TestSessionParams<BinaryFormat>;
    type P = DistributedRng;

    #[tokio::test]
    async fn async_run() {
        let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers
            .iter()
            .map(Keypair::verifying_key)
            .collect::<Vec<_>>();

        let private_data = 999;
        let shared_data = (1001, PartyGroup::new(&ids));

        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let session_id = SessionId::random(&mut rng);

        let sessions = signers
            .into_iter()
            .map(|signer| {
                Session::<TestSessionParams<BinaryFormat>, DistributedRng>::new(
                    session_id.clone(),
                    signer,
                    &private_data,
                    &shared_data,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let results =
            run_async::<SP, P, _, ChaCha8Rng>(&mut rng, sessions, run_session::<SP, P>)
                .await
                .unwrap();

        let value = results.reports[&ids[0]].success_ref().unwrap();
        assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
        assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
    }
}
