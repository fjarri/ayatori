use alloc::{collections::BTreeMap, format, vec::Vec};

use crate::{
    entities::{Message, MessageId, RuntimeError},
    execution::{Session, SessionReport, SessionState, SessionUpdate, Task},
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
        let mut session_updated = false;

        let sessions_to_process = core::mem::take(&mut sessions);

        for mut session in sessions_to_process {
            let id = session.verifier().clone();

            let mut updates = Vec::new();
            for message in messages
                .get_mut(&id)
                .ok_or_else(|| RuntimeError::new(format!("{id:?} not found in the map of message queues")))?
                .drain(..)
            {
                let message_id = MessageId::random(rng).or_with_context(|| "Failed to create a message ID".into())?;
                updates.push(SessionUpdate::add_message(message_id, message));
            }

            loop {
                let update = if let Some(update) = updates.pop() {
                    update
                } else if let Some(task) = session.make_task().or_with_context(|| "Failed to make a task".into())? {
                    match task {
                        Task::Deterministic(task) => task.execute(),
                        Task::Randomized(task) => task.execute(rng),
                        Task::Send(task) => {
                            let (message, result) = task.unpack();
                            let destination = message.destination().clone();
                            messages
                                .get_mut(&destination)
                                .ok_or_else(|| {
                                    RuntimeError::new(format!("{id:?} not found in the map of message queues"))
                                })?
                                .push(message);
                            result.success()
                        }
                    }
                } else {
                    sessions.push(session);
                    break;
                };

                session_updated = true;

                session = match session.with_update(update)? {
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

        if !session_updated {
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
