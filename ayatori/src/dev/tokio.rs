//! `tokio`-specific tools for testing sessions.

use alloc::{collections::BTreeMap, format, sync::Arc, vec::Vec};

use rand::RngExt;
use signature::rand_core::UnwrapErr;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use super::run_sync::ExecutionResult;
use crate::{
    entities::{MessageId, RuntimeError},
    execution::{
        SendTask, Session, SessionReport,
        tokio::{MessageIn, MessageOut, SessionRunner},
    },
    traced_error::TraceableResult,
    traits::{ExecutableProtocol, SessionParameters},
};

struct WrappedMessageOut<SP: SessionParameters> {
    message: MessageOut<SP>,
    source: SP::Verifier,
}

async fn message_dispatcher<SP>(
    mut rng: SP::Rng,
    txs: BTreeMap<SP::Verifier, mpsc::Sender<MessageIn<SP>>>,
    rx: mpsc::Receiver<WrappedMessageOut<SP>>,
) -> Result<(), RuntimeError>
where
    SP: SessionParameters,
{
    let mut rx = rx;
    let mut messages = Vec::<(SP::Verifier, SendTask<SP>)>::new();

    loop {
        let mut messages_out = Vec::<WrappedMessageOut<SP>>::new();

        // Wait for a message to appear in the channel, or the channel to be closed.
        let Some(msg_out) = rx.recv().await else {
            return Ok(());
        };
        messages_out.push(msg_out);

        // Fetch all the messages currently in the channel.
        while let Ok(msg_out) = rx.try_recv() {
            messages_out.push(msg_out);
        }

        for msg_out in messages_out {
            match msg_out.message {
                MessageOut::Message(task) => {
                    messages.push((msg_out.source, task));
                }
                MessageOut::Error(error) => return Err(RuntimeError::new(format!("{error}"))),
            }
        }

        while !messages.is_empty() {
            // Pull a random message from the list,
            // to increase the chances that they are delivered out of order.
            let mut infallible_rng = UnwrapErr(&mut rng);
            let message_idx = infallible_rng.random_range(0..messages.len());
            let (source, outgoing) = messages.swap_remove(message_idx);

            let (message, result) = outgoing.execute();

            let tx = txs.get(message.destination()).ok_or_else(|| {
                RuntimeError::new(format!(
                    "Destination ({:?}) is missing in the map of channels",
                    message.destination()
                ))
            })?;

            let message_id = MessageId::random(&mut rng).or_with_context(|| "Failed to create a message ID".into())?;
            let msg_in = MessageIn::Message {
                message,
                id: message_id,
            };

            tx.send(msg_in)
                .await
                .map_err(|err| RuntimeError::new(format!("Could not send an outgoing message: {err}")))?;

            let source_tx = txs
                .get(&source)
                .ok_or_else(|| RuntimeError::new(format!("Source ({source:?}) is missing in the map of channels")))?;

            source_tx
                .send(MessageIn::Update(result.success()))
                .await
                .map_err(|err| RuntimeError::new(format!("Could not send back the result: {err}")))?;

            // Give up execution so that the tasks could process messages.
            tokio::time::sleep(tokio::time::Duration::from_millis(0)).await;
        }
    }
}

impl<'a, SP, P, F, Fut> SessionRunner<'a, SP, P> for F
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
    F: 'static
        + Send
        + Sync
        + Fn(
            &'a mut SP::Rng,
            &'a mpsc::Sender<MessageOut<SP>>,
            &'a mut mpsc::Receiver<MessageIn<SP>>,
            CancellationToken,
            Session<SP, P>,
        ) -> Fut,
    Fut: Send + Future<Output = Result<SessionReport<SP, P>, RuntimeError>> + 'a,
{
    type Fut = Fut;
    fn call(
        &self,
        rng: &'a mut SP::Rng,
        tx: &'a mpsc::Sender<MessageOut<SP>>,
        rx: &'a mut mpsc::Receiver<MessageIn<SP>>,
        cancellation: CancellationToken,
        session: Session<SP, P>,
    ) -> Self::Fut {
        self(rng, tx, rx, cancellation, session)
    }
}

/// Executes the given sessions concurrently within a `tokio` runtime.
pub async fn run_sessions_async<SP, P, F>(
    rng: &mut SP::Rng,
    sessions: Vec<Session<SP, P>>,
    session_runner: F,
) -> Result<ExecutionResult<SP, P>, RuntimeError>
where
    SP: SessionParameters,
    SP::Signer: Send + Sync,
    SP::Rng: Clone + Send,
    P: ExecutableProtocol<SP>,
    F: for<'a> SessionRunner<'a, SP, P>,
{
    let mut tx_map = BTreeMap::new();
    let mut session_handles = BTreeMap::new();
    let mut forwarding_handles = Vec::new();
    let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<WrappedMessageOut<SP>>(100);

    let cancellation = CancellationToken::new();
    let session_runner = Arc::new(session_runner);

    for session in sessions {
        let mut rng = rng.clone();
        let id = session.verifier().clone();
        let cancellation = cancellation.clone();
        let session_runner = session_runner.clone();

        let (in_tx, mut in_rx) = mpsc::channel::<MessageIn<SP>>(100);
        tx_map.insert(id.clone(), in_tx);

        let (out_tx, mut out_rx) = mpsc::channel::<MessageOut<SP>>(100);
        let dispatcher_tx = dispatcher_tx.clone();

        // We need to match the outgoing messages with their source
        // to be able to send back results of attempting to send a message.
        let source = id.clone();
        let forwarding_task: JoinHandle<Result<(), RuntimeError>> = tokio::spawn(async move {
            while let Some(message) = out_rx.recv().await {
                dispatcher_tx
                    .send(WrappedMessageOut {
                        source: source.clone(),
                        message,
                    })
                    .await
                    .map_err(|err| RuntimeError::new(format!("Failed to forward a message: {err}")))?;
            }
            Ok(())
        });
        forwarding_handles.push(forwarding_task);

        let node_task = async move {
            session_runner
                .call(&mut rng, &out_tx, &mut in_rx, cancellation, session)
                .await
        };
        session_handles.insert(id, tokio::spawn(node_task));
    }

    // Drop the last copy of the dispatcher's incoming channel so that it can finish.
    drop(dispatcher_tx);

    let dispatcher_task = message_dispatcher(rng.clone(), tx_map, dispatcher_rx);
    let dispatcher = tokio::spawn(dispatcher_task);

    let mut reports = BTreeMap::new();
    for (id, handle) in session_handles {
        reports.insert(
            id.clone(),
            handle
                .await
                .map_err(|err| RuntimeError::new(format!("Could not join the task of {id:?}: {err}")))??,
        );
    }

    for handle in forwarding_handles {
        handle
            .await
            .map_err(|err| RuntimeError::new(format!("Could not join the forwarding task: {err}")))??;
    }

    dispatcher
        .await
        .map_err(|err| RuntimeError::new(format!("Could not join the message dispatcher task: {err}")))??;

    Ok(ExecutionResult { reports })
}
