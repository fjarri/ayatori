//! `tokio`-specific tools for running sessions.

use signature::rand_core::CryptoRngCore;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::session::{MessageAttributableError, Session, SessionReport};
use crate::{
    entities::{Message, MessageId, UnattributableError},
    traits::{ExecutableProtocol, SessionParameters},
};

/// A container for incoming messages.
#[derive(Debug)]
pub struct MessageIn<SP: SessionParameters> {
    /// The message itself.
    pub message: Message<SP>,
    /// The ID associated with it.
    ///
    /// Will be used to identify the message if there is a problem with it that cannot be attributed to a party ID.
    pub id: MessageId<SP>,
}

/// A container for outgoing messages or non-fatal errors.
#[derive(Debug)]
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
    type Fut: Future<Output = Result<SessionReport<SP, P>, UnattributableError>> + 'a + Send;

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
