use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ayatori::protocol_user_api::{
    ExecutableProtocol, RuntimeError, Session, SessionParameters, SessionReport,
    SessionState, SessionUpdate, Task, tokio::MessageOut,
};

// ANCHOR: signature
pub async fn run_session<SP, P>(
    rng: &mut SP::Rng,
    tx: &mpsc::Sender<MessageOut<SP>>,
    rx: &mut mpsc::Receiver<SessionUpdate<SP>>,
    cancellation: CancellationToken,
    mut session: Session<SP, P>,
) -> Result<SessionReport<SP, P>, RuntimeError>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    // ANCHOR_END: signature

    // ANCHOR: event_loop
    let mut cached_update = None;
    loop {
        // ANCHOR_END: event_loop
        // ANCHOR: task_loop
        loop {
            let update = if let Some(update) = cached_update.take() {
                update
            } else if let Some(task) = session.make_task().unwrap() {
                match task {
                    // ANCHOR_END: task_loop
                    // ANCHOR: task_deterministic
                    Task::Deterministic(task) => task.execute(),
                    // ANCHOR_END: task_deterministic
                    // ANCHOR: task_randomized
                    Task::Randomized(task) => task.execute(rng),
                    // ANCHOR_END: task_randomized
                    // ANCHOR: task_send
                    Task::Send(task) => {
                        tx.send(MessageOut::Message(task)).await.unwrap();
                        continue;
                    } // ANCHOR_END: task_send
                      // ANCHOR: task_loop_end
                }
            } else {
                break;
            };
            // ANCHOR_END: task_loop_end

            // ANCHOR: with_update
            session = match session.with_update(update)? {
                // ANCHOR_END: with_update
                // ANCHOR: with_update_in_progress
                SessionState::InProgress(session) => session,
                // ANCHOR_END: with_update_in_progress
                // ANCHOR: with_update_message_error
                SessionState::InProgressWithMessageError { error, session } => {
                    tx.send(MessageOut::Error(error)).await.unwrap();
                    session
                }
                // ANCHOR_END: with_update_message_error
                // ANCHOR: with_update_reached_output
                SessionState::ReachedOutput(success) => {
                    return success.finalize();
                }
                // ANCHOR_END: with_update_reached_output
                // ANCHOR: with_update_unfinishable
                SessionState::Unfinishable(report) => return Ok(report),
            }
            // ANCHOR_END: with_update_unfinishable
        }

        // ANCHOR: get_message
        cached_update = Some(tokio::select! {
            message_in = rx.recv() => message_in.ok_or_else(|| {
                RuntimeError::new("Failed to pop a message from the input channel")
            })?,
            () = cancellation.cancelled() => return Ok(session.terminate()),
        });
        // ANCHOR_END: get_message
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ayatori::{
        dev::{
            BinaryFormat, TestSessionParams, TestSigner, tokio::run_sessions_async,
        },
        protocol_user_api::{Session, SessionId, ThresholdGroup},
        signature::{Keypair, rand_core::SeedableRng},
    };
    use rand_chacha::ChaCha8Rng;

    use super::run_session;
    use crate::distributed_rng::DistributedRng;

    type SP = TestSessionParams<BinaryFormat, ChaCha8Rng>;
    type P = DistributedRng;

    #[tokio::test]
    async fn async_run() {
        let signers = (1..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers
            .iter()
            .map(Keypair::verifying_key)
            .collect::<Vec<_>>();

        let private_data = 999;
        let shared_data = (1001, ThresholdGroup::new(&ids));

        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let session_id = SessionId::random(&mut rng).unwrap();

        let sessions = signers
            .into_iter()
            .map(|signer| {
                Session::<SP, P>::new(
                    session_id.clone(),
                    signer,
                    &private_data,
                    &shared_data,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let results =
            run_sessions_async::<SP, P, _>(&mut rng, sessions, run_session::<SP, P>)
                .await
                .unwrap();

        let value = results.reports[&ids[0]].success_ref().unwrap();
        assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
        assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
    }
}
