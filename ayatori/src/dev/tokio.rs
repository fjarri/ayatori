//! `tokio`-specific tools for testing sessions.

use alloc::{collections::BTreeMap, format, sync::Arc, vec::Vec};

use rand::Rng;
use signature::rand_core::CryptoRngCore;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::run_sync::ExecutionResult;
use crate::{
    entities::{Message, MessageId, RuntimeError},
    execution::{
        Session, SessionError, SessionReport,
        tokio::{MessageIn, MessageOut, SessionRunner},
    },
    traits::{ExecutableProtocol, SessionParameters},
};

async fn message_dispatcher<SP>(
    rng: impl CryptoRngCore,
    txs: BTreeMap<SP::Verifier, mpsc::Sender<MessageIn<SP>>>,
    rx: mpsc::Receiver<MessageOut<SP>>,
) -> Result<(), RuntimeError>
where
    SP: SessionParameters,
{
    let mut rng = rng;

    let mut rx = rx;
    let mut messages = Vec::<Message<SP>>::new();
    loop {
        let mut messages_out = Vec::<MessageOut<SP>>::new();

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
            let message = match msg_out {
                MessageOut::Message(message) => message,
                MessageOut::Error(error) => return Err(RuntimeError::new(format!("{error}"))),
            };

            messages.push(message);
        }

        while !messages.is_empty() {
            // Pull a random message from the list,
            // to increase the chances that they are delivered out of order.
            let message_idx = rng.gen_range(0..messages.len());
            let outgoing = messages.swap_remove(message_idx);

            let tx = txs.get(outgoing.destination()).ok_or_else(|| {
                RuntimeError::new(format!(
                    "Destination ({:?}) is missing in the map of channels",
                    outgoing.destination()
                ))
            })?;

            let message_id = MessageId::random(&mut rng);
            let msg_in = MessageIn::Message {
                message: outgoing,
                id: message_id,
            };

            tx.send(msg_in)
                .await
                .map_err(|err| RuntimeError::new(format!("Could not sent an outgoing message: {err}")))?;

            // Give up execution so that the tasks could process messages.
            tokio::time::sleep(tokio::time::Duration::from_millis(0)).await;
        }
    }
}

impl<'a, SP, P, F, Fut, R> SessionRunner<'a, SP, P, R> for F
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
    R: CryptoRngCore + 'a,
    F: 'static
        + Send
        + Sync
        + Fn(
            &'a mut R,
            &'a mpsc::Sender<MessageOut<SP>>,
            &'a mut mpsc::Receiver<MessageIn<SP>>,
            CancellationToken,
            Session<SP, P>,
        ) -> Fut,
    Fut: Send + Future<Output = Result<SessionReport<SP, P>, SessionError>> + 'a,
{
    type Fut = Fut;
    fn call(
        &self,
        rng: &'a mut R,
        tx: &'a mpsc::Sender<MessageOut<SP>>,
        rx: &'a mut mpsc::Receiver<MessageIn<SP>>,
        cancellation: CancellationToken,
        session: Session<SP, P>,
    ) -> Self::Fut {
        self(rng, tx, rx, cancellation, session)
    }
}

/// Executes the given sessions concurrently within a `tokio` runtime.
pub async fn run_sessions_async<SP, P, F, R>(
    rng: &mut R,
    sessions: Vec<Session<SP, P>>,
    session_runner: F,
) -> Result<ExecutionResult<SP, P>, SessionError>
where
    R: 'static + CryptoRngCore + Clone + Send,
    SP: SessionParameters,
    SP::Signer: Send + Sync,
    P: ExecutableProtocol<SP>,
    F: for<'a> SessionRunner<'a, SP, P, R>,
{
    let num_parties = sessions.len();

    let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<MessageOut<SP>>(100);

    let channels = (0..num_parties).map(|_| mpsc::channel::<MessageIn<SP>>(100));
    let (txs, rxs): (Vec<_>, Vec<_>) = channels.unzip();
    let tx_map = sessions
        .iter()
        .map(|session| session.verifier().clone())
        .zip(txs)
        .collect();

    let dispatcher_task = message_dispatcher(rng.clone(), tx_map, dispatcher_rx);
    let dispatcher = tokio::spawn(dispatcher_task);
    let cancellation = CancellationToken::new();

    let session_runner = Arc::new(session_runner);

    let handles = rxs
        .into_iter()
        .zip(sessions)
        .map(|(mut rx, session)| {
            let tx = dispatcher_tx.clone();
            let mut rng = rng.clone();

            let id = session.verifier().clone();
            let cancellation = cancellation.clone();
            let session_runner = session_runner.clone();

            let node_task = async move { session_runner.call(&mut rng, &tx, &mut rx, cancellation, session).await };
            Ok((id, tokio::spawn(node_task)))
        })
        .collect::<Result<BTreeMap<_, _>, SessionError>>()?;

    // Drop the last copy of the dispatcher's incoming channel so that it can finish.
    drop(dispatcher_tx);

    let mut reports = BTreeMap::new();
    for (id, handle) in handles {
        reports.insert(
            id.clone(),
            handle
                .await
                .map_err(|err| RuntimeError::new(format!("Could not join the task of {id:?}: {err}")))??,
        );
    }

    dispatcher
        .await
        .map_err(|err| RuntimeError::new(format!("Could not join the message dispatcher task: {err}")))??;

    Ok(ExecutionResult { reports })
}
