//! `tokio`-specific tools for running sessions.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use itertools::Itertools;
use rand_chacha::ChaCha20Rng;
use signature::rand_core::{CryptoRngCore, SeedableRng};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

use super::{
    session::{MessageAttributableError, Session, SessionError, SessionReport, SessionState, TaskError},
    task::{Task, TaskResult},
};
use crate::{
    entities::{Message, MessageId, RuntimeError},
    error::TraceableResult,
    traits::{ExecutableProtocol, SessionParameters},
};

/// A container for incoming commands to a session runner.
#[derive_where::derive_where(Debug)]
pub enum MessageIn<SP: SessionParameters> {
    /// An incoming message.
    Message {
        /// The message itself.
        message: Message<SP>,
        /// The ID associated with the message.
        ///
        /// Will be used to identify the message if there is a problem with it that cannot be attributed to a party ID.
        id: MessageId<SP>,
    },
    /// A request to ban the specified party.
    Ban {
        /// The party id to ban.
        id: SP::Verifier,
        /// The ban reason.
        reason: String,
    },
}

/// A container for outgoing information from a session runner.
#[derive_where::derive_where(Debug)]
pub enum MessageOut<SP: SessionParameters> {
    /// A message that needs to be sent out.
    Message(Message<SP>),
    /// A non-fatal problem attributable to message(s) but not to a specific party.
    Error(MessageAttributableError<SP>),
}

/// A trait defined for `async fn`s that execute a single session.
pub trait SessionRunner<'a, SP: SessionParameters, P: ExecutableProtocol<SP>, R: CryptoRngCore>:
    'static + Send + Sync
{
    /// The returned future.
    type Fut: Future<Output = Result<SessionReport<SP, P>, SessionError>> + 'a + Send;

    /// Calls the function returning the future.
    fn call(
        &self,
        rng: &'a mut R,
        tx: &'a mpsc::Sender<MessageOut<SP>>,
        rx: &'a mut mpsc::Receiver<MessageIn<SP>>,
        cancellation: CancellationToken,
        session: Session<SP, P>,
    ) -> Self::Fut;
}

/// Executes the session waiting for the messages from the `rx` channel
/// and pushing outgoing messages into the `tx` channel.
pub async fn run_session<SP, P>(
    rng: &mut (impl CryptoRngCore + Send),
    tx: &mpsc::Sender<MessageOut<SP>>,
    rx: &mut mpsc::Receiver<MessageIn<SP>>,
    cancellation: CancellationToken,
    mut session: Session<SP, P>,
) -> Result<SessionReport<SP, P>, SessionError>
where
    SP: SessionParameters,
    SP::Signer: Sync,
    P: ExecutableProtocol<SP>,
{
    loop {
        while let Some(task) = session.make_task().or_with_context(|| "Failed to make a task".into())? {
            let task_result = match task {
                Task::Compute(task) => {
                    let result = task.execute();
                    session.add_result(result)
                }
                Task::ComputeWithRng(task) => {
                    let result = task.execute(rng);
                    session.add_result(result)
                }
                Task::Send(task) => {
                    let (message, result) = task.execute();
                    if let Some(message) = message {
                        tx.send(MessageOut::Message(message)).await.map_err(|err| {
                            RuntimeError::new(format!("Failed to send a message to the output channel: {err}"))
                        })?;
                    }
                    session.add_result(result)
                }
            };

            match task_result {
                Ok(()) => {}
                Err(TaskError::Runtime(error)) => return Err(error.into()),
                Err(TaskError::Spurious(error)) => return Err(error.into()),
                Err(TaskError::MessageAttributable(error)) => {
                    tx.send(MessageOut::Error(error)).await.map_err(|err| {
                        RuntimeError::new(format!("Failed to send a message to the output channel: {err}"))
                    })?;
                }
            }
        }

        session = match session.try_finalize() {
            SessionState::InProgress(session) => session,
            SessionState::ReachedOutput(success) => return Ok(success.finalize()?),
            SessionState::Stalled(stalled) => return Ok(stalled.finalize()),
        };

        let message_in = tokio::select! {
            message_in = rx.recv() => message_in.ok_or_else(|| {
                RuntimeError::new("Failed to pop a message from the input channel")
            })?,
            () = cancellation.cancelled() => return Ok(session.terminate()),
        };

        match message_in {
            MessageIn::Message { message, id } => session.add_message(&id, message),
            MessageIn::Ban { id, reason } => session.register_banned_party(id, reason),
        }
    }
}

struct TaskScope<SP: SessionParameters>(JoinSet<Result<TaskResult<SP>, RuntimeError>>);

impl<SP: SessionParameters> TaskScope<SP> {
    fn new() -> Self {
        Self(JoinSet::new())
    }

    fn spawn<F>(&mut self, task: F)
    where
        F: Future<Output = Result<TaskResult<SP>, RuntimeError>> + Send + 'static,
    {
        self.0.spawn(task);
    }

    fn spawn_blocking<F>(&mut self, f: F)
    where
        F: FnOnce() -> Result<TaskResult<SP>, RuntimeError> + Send + 'static,
    {
        self.0.spawn_blocking(f);
    }

    async fn join_next(&mut self) -> Option<Result<TaskResult<SP>, RuntimeError>> {
        self.0.join_next().await.map(|join_result| match join_result {
            Ok(result) => result,
            Err(err) => Err(RuntimeError::new(format!("Failed to join the task: {err}"))),
        })
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    // Aborts all tasks, waits for them to finish, and if there were errors in the results, returns them.
    async fn shutdown(&mut self) -> Result<(), RuntimeError> {
        self.0.abort_all();
        let mut errors = Vec::new();
        while let Some(result) = self.0.join_next().await {
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => errors.push(error),
                // Skip the expected errors due to cancellation, but report all the rest.
                Err(error) => {
                    if !error.is_cancelled() {
                        errors.push(RuntimeError::new(format!("Unexpected JoinError: {error}")));
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError::new(format!(
                "Errors during task shutdown:\n{}",
                errors.iter().map(ToString::to_string).join("\n")
            )))
        }
    }
}

// Since:
// - we want to avoid having dangling tasks when we return
// - we have multiple exit points from the function
// we wrap all the logic here so that we could clean all the tasks in one place (in the caller).
async fn par_run_session_inner<SP, P>(
    tasks: &mut TaskScope<SP>,
    rng: &mut impl CryptoRngCore,
    tx: &mpsc::Sender<MessageOut<SP>>,
    rx: &mut mpsc::Receiver<MessageIn<SP>>,
    cancellation: CancellationToken,
    mut session: Session<SP, P>,
) -> Result<SessionReport<SP, P>, SessionError>
where
    SP: SessionParameters,
    SP::Signer: Send + Sync,
    P: ExecutableProtocol<SP>,
{
    loop {
        while let Some(task) = session.make_task().or_with_context(|| "Failed to make a task".into())? {
            match task {
                Task::Compute(task) => {
                    tasks.spawn_blocking(move || Ok(task.execute()));
                }
                Task::ComputeWithRng(task) => {
                    let mut task_rng = ChaCha20Rng::from_rng(&mut *rng)
                        .map_err(|err| RuntimeError::new(format!("Failed to create an RNG: {err}")))?;
                    tasks.spawn_blocking(move || Ok(task.execute(&mut task_rng)));
                }
                Task::Send(task) => {
                    let tx = tx.clone();
                    tasks.spawn(async move {
                        let (message, result) = task.execute();
                        if let Some(message) = message {
                            tx.send(MessageOut::Message(message)).await.map_err(|err| {
                                RuntimeError::new(format!("Failed to send a message to the outbound channel: {err}"))
                            })?;
                        }
                        Ok(result)
                    });
                }
            }
        }

        tokio::select! {
            message_in = rx.recv() => {
                let message_in = message_in.ok_or_else(|| {
                    RuntimeError::new("Failed to pop an incoming message from the input channel")
                })?;
                match message_in {
                    MessageIn::Message { message, id } => session.add_message(&id, message),
                    MessageIn::Ban { id, reason } => session.register_banned_party(id, reason),
                }
            }
            task_result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(task_result) = task_result {
                    let task_result = task_result?;
                    match session.add_result(task_result) {
                        Ok(()) => {}
                        Err(TaskError::Runtime(error)) => return Err(error.into()),
                        Err(TaskError::Spurious(error)) => return Err(error.into()),
                        Err(TaskError::MessageAttributable(error)) => {
                            tx.send(MessageOut::Error(error)).await.map_err(|err| {
                                RuntimeError::new(format!("Failed to send a message to the output channel: {err}"))
                            })?;
                        }
                    }
                }
            }
            () = cancellation.cancelled() => return Ok(session.terminate()),
        };

        session = match session.try_finalize() {
            SessionState::InProgress(session) => session,
            SessionState::ReachedOutput(success) => return Ok(success.finalize()?),
            SessionState::Stalled(stalled) => return Ok(stalled.finalize()),
        };
    }
}

/// Executes the session waiting for the messages from the `rx` channel
/// and pushing outgoing messages into the `tx` channel.
/// The messages are processed in parallel.
///
/// This function should be used if message creation and verification takes a significant amount of time,
/// to offset the parallelizing overhead.
/// Use [`tokio::run_sessions_async`](`crate::dev::tokio::run_sessions_async`) to benchmark your specific protocol.
pub async fn par_run_session<SP, P>(
    rng: &mut impl CryptoRngCore,
    tx: &mpsc::Sender<MessageOut<SP>>,
    rx: &mut mpsc::Receiver<MessageIn<SP>>,
    cancellation: CancellationToken,
    session: Session<SP, P>,
) -> Result<SessionReport<SP, P>, SessionError>
where
    SP: SessionParameters,
    SP::Signer: Send + Sync,
    P: ExecutableProtocol<SP>,
{
    let mut tasks = TaskScope::new();
    let result = par_run_session_inner(&mut tasks, rng, tx, rx, cancellation, session).await;
    tasks.shutdown().await?;
    result
}
