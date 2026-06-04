//! `tokio`-specific tools for running sessions.

use alloc::{format, string::ToString, vec::Vec};

use itertools::Itertools;
use signature::rand_core::{SeedableRng, TryRng};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

use super::{
    session::{MessageAttributableError, Session, SessionReport, SessionState},
    task::{SendTask, SessionUpdate, Task},
};
use crate::{
    entities::RuntimeError,
    traced_error::TraceableResult,
    traits::{ExecutableProtocol, SessionParameters},
};

/// A container for outgoing information from a session runner.
#[derive_where::derive_where(Debug)]
pub enum MessageOut<SP: SessionParameters> {
    /// A message that needs to be sent out.
    Message(SendTask<SP>),
    /// A non-fatal problem attributable to message(s) but not to a specific party.
    Error(MessageAttributableError<SP>),
}

/// A trait defined for `async fn`s that execute a single session.
pub trait SessionRunner<'a, SP: SessionParameters, P: ExecutableProtocol<SP>>: 'static + Send + Sync {
    /// The returned future.
    type Fut: Future<Output = Result<SessionReport<SP, P>, RuntimeError>> + 'a + Send;

    /// Calls the function returning the future.
    fn call(
        &self,
        rng: &'a mut SP::Rng,
        tx: &'a mpsc::Sender<MessageOut<SP>>,
        rx: &'a mut mpsc::Receiver<SessionUpdate<SP>>,
        cancellation: CancellationToken,
        session: Session<SP, P>,
    ) -> Self::Fut;
}

/// Executes the session waiting for the messages from the `rx` channel
/// and pushing outgoing messages into the `tx` channel.
pub async fn run_session<SP, P>(
    rng: &mut SP::Rng,
    tx: &mpsc::Sender<MessageOut<SP>>,
    rx: &mut mpsc::Receiver<SessionUpdate<SP>>,
    cancellation: CancellationToken,
    mut session: Session<SP, P>,
) -> Result<SessionReport<SP, P>, RuntimeError>
where
    SP: SessionParameters,
    SP::Signer: Sync,
    SP::Rng: Send,
    P: ExecutableProtocol<SP>,
{
    let mut cached_update = None;
    loop {
        loop {
            let update = if let Some(update) = cached_update.take() {
                update
            } else if let Some(task) = session.make_task().or_with_context(|| "Failed to make a task".into())? {
                match task {
                    Task::Deterministic(task) => task.execute(),
                    Task::Randomized(task) => task.execute(rng),
                    Task::Send(task) => {
                        tx.send(MessageOut::Message(task)).await.map_err(|err| {
                            RuntimeError::new(format!("Failed to send a message to the output channel: {err}"))
                        })?;
                        continue;
                    }
                }
            } else {
                break;
            };

            session = match session.with_update(update)? {
                SessionState::InProgress(session) => session,
                SessionState::InProgressWithMessageError { error, session } => {
                    tx.send(MessageOut::Error(error)).await.map_err(|err| {
                        RuntimeError::new(format!("Failed to send a message to the output channel: {err}"))
                    })?;
                    session
                }
                SessionState::ReachedOutput(success) => {
                    return success.finalize();
                }
                SessionState::Unfinishable(report) => return Ok(report),
            }
        }

        cached_update = Some(tokio::select! {
            update = rx.recv() => update.ok_or_else(|| {
                RuntimeError::new("Failed to pop a message from the input channel")
            })?,
            () = cancellation.cancelled() => return Ok(session.terminate()),
        });
    }
}

struct TaskScope<SP: SessionParameters>(JoinSet<Result<SessionUpdate<SP>, RuntimeError>>);

impl<SP: SessionParameters> TaskScope<SP> {
    fn new() -> Self {
        Self(JoinSet::new())
    }

    fn spawn_blocking<F>(&mut self, f: F)
    where
        F: FnOnce() -> Result<SessionUpdate<SP>, RuntimeError> + Send + 'static,
    {
        self.0.spawn_blocking(f);
    }

    async fn join_next(&mut self) -> Option<Result<SessionUpdate<SP>, RuntimeError>> {
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
    rng: &mut SP::Rng,
    tx: &mpsc::Sender<MessageOut<SP>>,
    rx: &mut mpsc::Receiver<SessionUpdate<SP>>,
    cancellation: CancellationToken,
    mut session: Session<SP, P>,
) -> Result<SessionReport<SP, P>, RuntimeError>
where
    SP: SessionParameters,
    SP::Signer: Send + Sync,
    SP::Rng: SeedableRng + Send,
    P: ExecutableProtocol<SP>,
{
    loop {
        while let Some(task) = session.make_task().or_with_context(|| "Failed to make a task".into())? {
            match task {
                Task::Deterministic(task) => {
                    tasks.spawn_blocking(move || Ok(task.execute()));
                }
                Task::Randomized(task) => {
                    let mut seed = <SP::Rng as SeedableRng>::Seed::default();
                    rng.try_fill_bytes(seed.as_mut())
                        .map_err(|err| RuntimeError::new(format!("Failed to fill buffer with random data: {err}")))?;
                    let mut task_rng = SP::Rng::from_seed(seed);
                    tasks.spawn_blocking(move || Ok(task.execute(&mut task_rng)));
                }
                Task::Send(task) => {
                    tx.send(MessageOut::Message(task)).await.map_err(|err| {
                        RuntimeError::new(format!("Failed to send a message to the outbound channel: {err}"))
                    })?;
                }
            }
        }

        let maybe_update = tokio::select! {
            update = rx.recv() => {
                let update = update.ok_or_else(|| {
                    RuntimeError::new("Failed to pop an incoming message from the input channel")
                })?;
                Some(update)
            }
            update = tasks.join_next(), if !tasks.is_empty() => {
                let update = update.ok_or_else(|| {
                    RuntimeError::new("Expected an update to be `Some` since we checked that the task set is not empty")
                })?;
                Some(update?)
            }
            () = cancellation.cancelled() => return Ok(session.terminate()),
        };

        if let Some(update) = maybe_update {
            session = match session.with_update(update)? {
                SessionState::InProgress(session) => session,
                SessionState::InProgressWithMessageError { error, session } => {
                    tx.send(MessageOut::Error(error)).await.map_err(|err| {
                        RuntimeError::new(format!("Failed to send a message to the output channel: {err}"))
                    })?;
                    session
                }
                SessionState::ReachedOutput(success) => {
                    return success.finalize();
                }
                SessionState::Unfinishable(report) => {
                    return Ok(report);
                }
            }
        }
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
    rng: &mut SP::Rng,
    tx: &mpsc::Sender<MessageOut<SP>>,
    rx: &mut mpsc::Receiver<SessionUpdate<SP>>,
    cancellation: CancellationToken,
    session: Session<SP, P>,
) -> Result<SessionReport<SP, P>, RuntimeError>
where
    SP: SessionParameters,
    SP::Signer: Send + Sync,
    SP::Rng: SeedableRng + Send,
    P: ExecutableProtocol<SP>,
{
    let mut tasks = TaskScope::new();
    let result = par_run_session_inner(&mut tasks, rng, tx, rx, cancellation, session).await;
    tasks.shutdown().await?;
    result
}
