use alloc::{collections::BTreeMap, format, vec::Vec};

use signature::rand_core::CryptoRngCore;

use crate::{
    entities::{Message, MessageId, UnattributableError},
    execution::{Session, SessionReport, SessionState, Task, TaskError},
    traits::{ExecutableProtocol, SessionParameters},
};

/// Executes the given sessions without offloading tasks to separate threads.
pub fn run_sessions_sync<SP: SessionParameters, P: ExecutableProtocol<SP>>(
    rng: &mut impl CryptoRngCore,
    sessions: Vec<Session<SP, P>>,
) -> Result<ExecutionResult<SP, P>, UnattributableError> {
    let mut sessions = sessions;
    let mut messages = sessions
        .iter()
        .map(|session| (session.verifier().clone(), Vec::<Message<SP>>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut reports = BTreeMap::new();

    let mut finished_with_success = Vec::new();
    let mut finished_with_stall = Vec::new();

    while !sessions.is_empty() {
        let mut task_processed = false;

        let sessions_to_process = core::mem::take(&mut sessions);

        for mut session in sessions_to_process {
            let id = session.verifier().clone();
            for message in messages
                .get_mut(&id)
                .ok_or_else(|| UnattributableError::runtime(format!("{id:?} not found in the map of message queues")))?
                .drain(..)
            {
                let message_id = MessageId::random(rng);
                session.add_message(&message_id, message);
            }

            while let Some(task) = session.make_task()? {
                let task_result = match task {
                    Task::Compute(task) => session.add_result(task.compute()),
                    Task::ComputeWithRng(task) => session.add_result(task.compute(rng)),
                    Task::Send(task) => {
                        let (message, result) = task.compute();
                        if let Some(message) = message {
                            let destination = message.destination().clone();
                            messages
                                .get_mut(&destination)
                                .ok_or_else(|| {
                                    UnattributableError::runtime(format!(
                                        "{id:?} not found in the map of message queues"
                                    ))
                                })?
                                .push(message);
                        }
                        session.add_result(result)
                    }
                };
                task_processed = true;

                match task_result {
                    Ok(()) => {}
                    Err(TaskError::Unattributable(error)) => return Err(error),
                    Err(TaskError::MessageAttributable(error)) => {
                        return Err(UnattributableError::runtime(format!(
                            "Message-attributable error: {error:?}"
                        )));
                    }
                }
            }

            match session.try_finalize() {
                SessionState::InProgress(session) => sessions.push(session),
                SessionState::ReachedOutput(success) => finished_with_success.push(success),
                SessionState::Stalled(stalled) => finished_with_stall.push(stalled),
            }
        }

        if !task_processed {
            return Err(UnattributableError::runtime(
                "Sessions are stuck: there are still active sessions, but no tasks are being created",
            ));
        }
    }

    for session in finished_with_success {
        let id = session.as_ref().verifier().clone();
        let report = session.finalize()?;
        reports.insert(id.clone(), report);
    }

    for session in finished_with_stall {
        let id = session.as_ref().verifier().clone();
        let report = session.finalize();
        reports.insert(id.clone(), report);
    }

    Ok(ExecutionResult { reports })
}

/// The result of executing sessions.
#[derive_where::derive_where(Debug)]
pub struct ExecutionResult<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    /// The combined reports of finished sessions.
    pub reports: BTreeMap<SP::Verifier, SessionReport<SP, P>>,
}
