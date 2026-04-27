use alloc::format;

use signature::rand_core::CryptoRngCore;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ayatori::protocol_user_api::*;

pub async fn run_session<SP, P>(
    rng: &mut impl CryptoRngCore,
    tx: &mpsc::Sender<Message<SP>>,
    rx: &mut mpsc::Receiver<Message<SP>>,
    cancellation: CancellationToken,
    session: Session<SP, P>,
) -> Result<SessionReport<SP, P>, UnattributableError>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    let mut session = session;

    loop {
        while let Some(task) = session.make_task()? {
            let task_result = match task {
                Task::Compute(task) => {
                    let result = task.compute()?;
                    session.add_result(result)
                }
                Task::ComputeWithRng(task) => {
                    let result = task.compute(rng)?;
                    session.add_result(result)
                }
                Task::Send(task) => {
                    let (message, result) = task.compute()?;
                    tx.send(message).await.map_err(|err| {
                        UnattributableError::runtime(format!(
                            "Failed to send a message: {err}"
                        ))
                    })?;
                    session.add_result(result)
                }
                Task::FinalizeWithSuccess(token) => {
                    return Ok(session.finalize_with_success(token)?);
                }
                Task::FinalizeWithStalled(token) => {
                    return Ok(session.finalize_with_stalled(token));
                }
            };

            match task_result {
                Ok(()) => {}
                Err(TaskError::Unattributable(error)) => return Err(error),
                Err(TaskError::InvalidMessage(error)) => {
                    return Err(UnattributableError::runtime(format!(
                        "Invalid message: {error:?}"
                    )));
                }
                Err(TaskError::DuplicateMessages(error)) => {
                    return Err(UnattributableError::runtime(format!(
                        "Duplicate messages: {error:?}"
                    )));
                }
            }
        }

        let message_in = tokio::select! {
            message_in = rx.recv() => {
                message_in.ok_or_else(|| {
                    UnattributableError::runtime(
                        "The incoming message channel was closed unexpectedly"
                    )
                })?
            },
            () = cancellation.cancelled() => {
                return Ok(session.terminate());
            }
        };

        let message_id = MessageId::random(rng);
        session.add_message(&message_id, message_in);
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

        let group = PartyGroup::new(&ids);
        let private_data = signers.into_iter().map(|signer| (signer, 999u32)).collect();
        let shared_data = (1001, group);

        let mut rng = ChaCha8Rng::seed_from_u64(123);

        let results = run_async::<SP, P, _, ChaCha8Rng>(
            &mut rng,
            shared_data,
            private_data,
            run_session::<SP, P>,
        )
        .await
        .unwrap();

        let value = results.reports[&ids[0]].success_ref().unwrap();
        assert_eq!(results.reports[&ids[1]].success_ref().unwrap(), value);
        assert_eq!(results.reports[&ids[2]].success_ref().unwrap(), value);
    }
}
