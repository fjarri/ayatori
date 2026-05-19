use alloc::{collections::BTreeMap, format, vec::Vec};

use crate::{
    entities::{Message, MessageId, RuntimeError},
    execution::{Session, SessionReport, SessionState, Task},
    traced_error::TraceableResult,
    traits::{ExecutableProtocol, SessionParameters},
};

/// Executes the given sessions without offloading tasks to separate threads.
pub fn run_sessions_sync<SP: SessionParameters, P: ExecutableProtocol<SP>>(
    rng: &mut SP::Rng,
    sessions: Vec<Session<SP, P>>,
) -> Result<ExecutionResult<SP, P>, RuntimeError> {
    let mut sessions = sessions;
    let mut messages = sessions
        .iter()
        .map(|session| (session.verifier().clone(), Vec::<Message<SP>>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut reports = BTreeMap::new();

    while !sessions.is_empty() {
        let mut task_processed = false;

        let sessions_to_process = core::mem::take(&mut sessions);

        for mut session in sessions_to_process {
            let id = session.verifier().clone();

            for message in messages
                .get_mut(&id)
                .ok_or_else(|| RuntimeError::new(format!("{id:?} not found in the map of message queues")))?
                .drain(..)
            {
                let message_id = MessageId::random(rng).or_with_context(|| "Failed to create a message ID".into())?;
                session.add_message(&message_id, message);
            }

            loop {
                let Some(task) = session.make_task().or_with_context(|| "Failed to make a task".into())? else {
                    sessions.push(session);
                    break;
                };

                task_processed = true;

                let new_state = match task {
                    Task::Deterministic(task) => session.add_result(task.execute()),
                    Task::Randomized(task) => session.add_result(task.execute(rng)),
                    Task::Send(task) => {
                        let (message, result) = task.execute();
                        if let Some(message) = message {
                            let destination = message.destination().clone();
                            messages
                                .get_mut(&destination)
                                .ok_or_else(|| {
                                    RuntimeError::new(format!("{id:?} not found in the map of message queues"))
                                })?
                                .push(message);
                        }
                        session.add_result(result)
                    }
                }?;

                session = match new_state {
                    SessionState::InProgress(session) => session,
                    SessionState::InProgressWithMessageError { error, .. } => {
                        return Err(RuntimeError::new(format!("Message-attributable error: {error:?}")));
                    }
                    SessionState::ReachedOutput(success) => {
                        let report = success.finalize()?;
                        reports.insert(id, report);
                        break;
                    }
                    SessionState::Unfinishable(report) => {
                        reports.insert(id, report);
                        break;
                    }
                };
            }
        }

        if !task_processed {
            // That's where in production the sessions would time out and get terminated externally.
            for session in sessions {
                reports.insert(session.verifier().clone(), session.terminate());
            }

            break;
        }
    }

    Ok(ExecutionResult { reports })
}

/// The result of executing sessions.
#[derive_where::derive_where(Debug)]
pub struct ExecutionResult<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    /// The combined reports of finished sessions.
    pub reports: BTreeMap<SP::Verifier, SessionReport<SP, P>>,
}
