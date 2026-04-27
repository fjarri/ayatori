use alloc::{collections::BTreeMap, format, sync::Arc, vec::Vec};

use signature::{Keypair, rand_core::CryptoRngCore};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::run_sync::ExecutionResult;
use crate::{
    entities::{Message, RuntimeError, SessionId, UnattributableError},
    execution::{Session, SessionReport},
    traits::{ExecutableProtocol, SessionParameters},
};

async fn message_dispatcher<SP>(
    rng: impl CryptoRngCore,
    txs: BTreeMap<SP::Verifier, mpsc::Sender<Message<SP>>>,
    rx: mpsc::Receiver<Message<SP>>,
) -> Result<(), RuntimeError>
where
    SP: SessionParameters,
{
    let mut rng = rng;

    let mut rx = rx;
    let mut messages = Vec::<Message<SP>>::new();
    loop {
        let Some(msg) = rx.recv().await else { return Ok(()) };
        messages.push(msg);

        while let Ok(msg) = rx.try_recv() {
            messages.push(msg);
        }

        while !messages.is_empty() {
            // Pull a random message from the list,
            // to increase the chances that they are delivered out of order.
            let message_idx = (rng.next_u32() as usize) % messages.len();
            let outgoing = messages.swap_remove(message_idx);

            txs.get(outgoing.destination())
                .ok_or_else(|| {
                    RuntimeError::new(format!(
                        "Destination ({:?}) is missing in the map of channels",
                        outgoing.destination()
                    ))
                })?
                .send(outgoing)
                .await
                .map_err(|err| RuntimeError::new(format!("Could not sent an outgoing message: {err}")))?;

            // Give up execution so that the tasks could process messages.
            tokio::time::sleep(tokio::time::Duration::from_millis(0)).await;

            if let Ok(msg) = rx.try_recv() {
                messages.push(msg);
            }
        }
    }
}

/// A trait defined for `async fn`s that execute a single session.
pub trait SessionRunner<'a, SP: SessionParameters, P: ExecutableProtocol<SP>, R: CryptoRngCore>:
    'static + Send + Sync
{
    /// The returned future.
    type Fut: Future<Output = Result<SessionReport<SP, P>, UnattributableError>> + 'a + Send;

    /// Calls the function returning the future.
    fn call(
        &self,
        rng: &'a mut R,
        tx: &'a mpsc::Sender<Message<SP>>,
        rx: &'a mut mpsc::Receiver<Message<SP>>,
        cancellation: CancellationToken,
        session: Session<SP, P>,
    ) -> Self::Fut;
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
            &'a mpsc::Sender<Message<SP>>,
            &'a mut mpsc::Receiver<Message<SP>>,
            CancellationToken,
            Session<SP, P>,
        ) -> Fut,
    Fut: Send + Future<Output = Result<SessionReport<SP, P>, UnattributableError>> + 'a,
{
    type Fut = Fut;
    fn call(
        &self,
        rng: &'a mut R,
        tx: &'a mpsc::Sender<Message<SP>>,
        rx: &'a mut mpsc::Receiver<Message<SP>>,
        cancellation: CancellationToken,
        session: Session<SP, P>,
    ) -> Self::Fut {
        self(rng, tx, rx, cancellation, session)
    }
}

/// Execute sessions for multiple nodes concurrently within a `tokio` runtime,
/// given a vector of the signer and the private data for each node.
pub async fn run_async<SP, P, F, R>(
    rng: &mut R,
    shared_data: P::SharedData,
    private_data: Vec<(SP::Signer, P::PrivateData)>,
    session_runner: F,
) -> Result<ExecutionResult<SP, P>, UnattributableError>
where
    R: 'static + CryptoRngCore + Clone + Send,
    SP: SessionParameters,
    SP::Signer: Send + Sync, // TODO: why Send?
    P: ExecutableProtocol<SP>,
    F: for<'a> SessionRunner<'a, SP, P, R>,
{
    let num_parties = private_data.len();
    let session_id = SessionId::random(rng);

    let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<Message<SP>>(100);

    let channels = (0..num_parties).map(|_| mpsc::channel::<Message<SP>>(100));
    let (txs, rxs): (Vec<_>, Vec<_>) = channels.unzip();
    let tx_map = private_data
        .iter()
        .map(|(signer, _private_data)| signer.verifying_key())
        .zip(txs)
        .collect();

    let dispatcher_task = message_dispatcher(rng.clone(), tx_map, dispatcher_rx);
    let dispatcher = tokio::spawn(dispatcher_task);
    let cancellation = CancellationToken::new();

    let sessions = private_data
        .into_iter()
        .map(|(signer, private_data)| Session::<SP, P>::new(session_id.clone(), signer, &private_data, &shared_data))
        .collect::<Result<Vec<_>, _>>()?;

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
        .collect::<Result<BTreeMap<_, _>, UnattributableError>>()?;

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
