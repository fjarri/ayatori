use signature::rand_core::CryptoRngCore;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ayatori::protocol_user_api::{
    ExecutableProtocol, RuntimeError, Session, SessionParameters, SessionReport,
    SessionState, Task,
    tokio::{MessageIn, MessageOut},
};

// ANCHOR: signature
pub async fn run_session<SP, P>(
    rng: &mut impl CryptoRngCore,
    tx: &mpsc::Sender<MessageOut<SP>>,
    rx: &mut mpsc::Receiver<MessageIn<SP>>,
    cancellation: CancellationToken,
    mut session: Session<SP, P>,
) -> Result<SessionReport<SP, P>, RuntimeError>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    // ANCHOR_END: signature

    // ANCHOR: event_loop
    loop {
        // ANCHOR_END: event_loop

        // ANCHOR: task_loop
        while let Some(task) = session.make_task()? {
            let new_state = match task {
                // ANCHOR_END: task_loop
                // ANCHOR: task_deterministic
                Task::Deterministic(task) => session.add_result(task.execute()),
                // ANCHOR_END: task_deterministic

                // ANCHOR: task_randomized
                Task::Randomized(task) => session.add_result(task.execute(rng)),
                // ANCHOR_END: task_randomized

                // ANCHOR: task_send
                Task::Send(task) => {
                    let (message, result) = task.execute();
                    if let Some(message) = message {
                        tx.send(MessageOut::Message(message)).await.unwrap();
                    }
                    session.add_result(result)
                } // ANCHOR_END: task_send
            };

            // ANCHOR: task_result
            session = match new_state? {
                // ANCHOR_END: task_result
                // ANCHOR: task_result_in_progress
                SessionState::InProgress(session) => session,
                // ANCHOR_END: task_result_in_progress
                // ANCHOR: task_result_message_error
                SessionState::InProgressWithMessageError { error, session } => {
                    tx.send(MessageOut::Error(error)).await.unwrap();
                    session
                }
                // ANCHOR_END: task_result_message_error
                // ANCHOR: task_result_reached_output
                SessionState::ReachedOutput(success) => {
                    return success.finalize();
                }
                // ANCHOR_END: task_result_reached_output
                // ANCHOR: task_result_unfinishable
                SessionState::Unfinishable(report) => {
                    return Ok(report);
                } // ANCHOR_END: task_result_unfinishable
            }
        }

        // ANCHOR: get_message
        let message_in = tokio::select! {
            message_in = rx.recv() => message_in.unwrap(),
            () = cancellation.cancelled() => return Ok(session.terminate()),
        };

        match message_in {
            MessageIn::Message { message, id } => session.add_message(&id, message),
            MessageIn::Ban { id, reason } => {
                session.register_banned_party(id, reason)
            }
        }
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
        protocol_user_api::{PartyGroup, Session, SessionId},
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
                Session::<SP, P>::new(
                    session_id.clone(),
                    signer,
                    &private_data,
                    &shared_data,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let results = run_sessions_async::<SP, P, _, ChaCha8Rng>(
            &mut rng,
            sessions,
            run_session::<SP, P>,
        )
        .await
        .unwrap();

        let value = results.reports[&ids[0]].success_ref().unwrap();
        assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
        assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
    }
}
