use alloc::{collections::BTreeMap, format, vec::Vec};

use crate::{
    entities::{FullName, Message, MessageId, RuntimeError},
    execution::{Session, SessionReport, SessionState, SessionUpdate, Task},
    traced_error::TraceableResult,
    traits::{ExecutableProtocol, SessionParameters},
};

/// A rule that determines if a specific protocol message will be blocked during execution
///
/// The node attempting to send it will have the message destination banned.
#[derive_where::derive_where(Debug, Default)]
pub struct BlockMessagesRule<SP: SessionParameters> {
    /// If `Some`, messages from this source will be blocked.
    /// If `None`, messages from any source will be blocked.
    pub source: Option<SP::Verifier>,
    /// If `Some`, messages from this destination will be blocked.
    /// If `None`, messages from any destination will be blocked.
    pub destination: Option<SP::Verifier>,
    /// If `Some`, messages with this name will be blocked.
    /// If `None`, messages with any name will be blocked.
    pub name: Option<FullName>,
}

/// A custom config for executing multiple sessions.
#[derive_where::derive_where(Debug, Default)]
pub struct RunSyncConfig<SP: SessionParameters> {
    block_messages: Vec<BlockMessagesRule<SP>>,
}

impl<SP: SessionParameters> RunSyncConfig<SP> {
    /// Adds a rule for blocking specific messages during execution.
    #[must_use]
    pub fn block_messages(mut self, rule: BlockMessagesRule<SP>) -> Self {
        self.block_messages.push(rule);
        self
    }

    fn filter_message(&self, message: Message<SP>) -> Option<Message<SP>> {
        if self.block_messages.is_empty() {
            return Some(message);
        }

        let mut filtered_values = message.into_values();
        for rule in &self.block_messages {
            filtered_values.retain(|value| {
                let metadata = value.metadata();
                let block_by_source = rule.source.as_ref().is_none_or(|source| source == value.source());
                let block_by_destination = rule
                    .destination
                    .as_ref()
                    .is_none_or(|destination| destination == metadata.destination());
                let block_by_name = rule.name.as_ref().is_none_or(|name| name == metadata.full_name());

                !(block_by_source && block_by_destination && block_by_name)
            });
        }

        if filtered_values.is_empty() {
            None
        } else {
            Some(
                Message::new(filtered_values)
                    .expect("the values vec is non-empty and they all still have the same destination"),
            )
        }
    }

    /// Executes the given sessions without offloading tasks to separate threads.
    pub fn run_sessions<P: ExecutableProtocol<SP>>(
        &self,
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
            let mut stalled = true;

            let sessions_to_process = core::mem::take(&mut sessions);

            for mut session in sessions_to_process {
                let id = session.verifier().clone();

                let mut updates = Vec::new();
                for message in messages
                    .get_mut(&id)
                    .ok_or_else(|| RuntimeError::new(format!("{id:?} not found in the map of message queues")))?
                    .drain(..)
                {
                    let message_id =
                        MessageId::random(rng).or_with_context(|| "Failed to create a message ID".into())?;
                    updates.push(SessionUpdate::add_message(message_id, message));
                }

                // TODO: ideally here we want to loop until all incoming messages are exhausted,
                // and all tasks are exhausted.
                loop {
                    // TODO: can this be made less awkward?
                    let update = if let Some(update) = updates.pop() {
                        stalled = false;
                        Some(update)
                    } else if let Some(task) = session.make_task().or_with_context(|| "Failed to make a task".into())? {
                        stalled = false;
                        match task {
                            Task::Deterministic(task) => Some(task.execute()),
                            Task::Randomized(task) => Some(task.execute(rng)),
                            Task::Send(message) => {
                                let destination = message.destination().clone();
                                let queue = messages.get_mut(&destination).ok_or_else(|| {
                                    RuntimeError::new(format!("{id:?} not found in the map of message queues"))
                                })?;

                                self.filter_message(message).map_or_else(
                                    || Some(SessionUpdate::ban_party(destination, "Unreahable")),
                                    |message| {
                                        queue.push(message);
                                        None
                                    },
                                )
                            }
                        }
                    } else {
                        None
                    };

                    let Some(update) = update else {
                        sessions.push(session);
                        break;
                    };

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

            if stalled {
                // That's where in production the sessions would time out and get terminated externally.
                for session in sessions {
                    reports.insert(session.verifier().clone(), session.terminate());
                }

                break;
            }
        }

        Ok(ExecutionResult { reports })
    }
}

/// Executes the given sessions with default [`RunSyncConfig`].
pub fn run_sessions_sync<SP: SessionParameters, P: ExecutableProtocol<SP>>(
    rng: &mut SP::Rng,
    sessions: Vec<Session<SP, P>>,
) -> Result<ExecutionResult<SP, P>, RuntimeError> {
    RunSyncConfig::default().run_sessions(rng, sessions)
}

/// The result of executing sessions.
#[derive_where::derive_where(Debug)]
pub struct ExecutionResult<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    /// The combined reports of finished sessions.
    pub reports: BTreeMap<SP::Verifier, SessionReport<SP, P>>,
}
