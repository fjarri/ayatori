use alloc::{collections::BTreeSet, vec::Vec};

use super::{session::MessageAttributableError, task::SendTask};
use crate::{entities::Message, traits::SessionParameters};

/// A static configuration of a session runner.
pub trait SessionRunnerConfiguration<SP: SessionParameters>: 'static {
    /// The type of messages sent to the outgoing channel.
    type MessageOut: 'static + Send + Sync + From<MessageAttributableError<SP>>;

    /// Converts [`SendTask`] into outgoing messages.
    fn send_task_into_messages_out(task: SendTask<SP>) -> impl Iterator<Item = Self::MessageOut>;

    /// Converts the outgoing messages into direct messages.
    #[expect(clippy::type_complexity)]
    #[cfg(feature = "dev")]
    fn message_out_into_dms(
        message_out: Self::MessageOut,
    ) -> Result<Vec<(SP::Verifier, Message<SP>)>, MessageAttributableError<SP>>;
}

/// A configuration that declares that the session runner only produces direct messages and no broadcasts.
#[derive(Debug, Clone, Copy)]
pub struct DirectMessagesOnly;

impl<SP: SessionParameters> SessionRunnerConfiguration<SP> for DirectMessagesOnly {
    type MessageOut = DMsOnlyMessageOut<SP>;

    fn send_task_into_messages_out(task: SendTask<SP>) -> impl Iterator<Item = Self::MessageOut> {
        task.into_dms()
            .into_iter()
            .map(|(destination, message)| DMsOnlyMessageOut::DirectMessage { destination, message })
    }

    #[cfg(feature = "dev")]
    fn message_out_into_dms(
        message_out: Self::MessageOut,
    ) -> Result<Vec<(SP::Verifier, Message<SP>)>, MessageAttributableError<SP>> {
        match message_out {
            DMsOnlyMessageOut::DirectMessage { destination, message } => Ok([(destination, message)].into()),
            DMsOnlyMessageOut::Error(error) => Err(error),
        }
    }
}

/// A configuration that declares that the session runner produces broadcasts and direct messages.
#[derive(Debug, Clone, Copy)]
pub struct BroadcastsSupported;

impl<SP: SessionParameters> SessionRunnerConfiguration<SP> for BroadcastsSupported {
    type MessageOut = BCsSupportedMessageOut<SP>;

    fn send_task_into_messages_out(task: SendTask<SP>) -> impl Iterator<Item = Self::MessageOut> {
        let (bcs, dms) = task.into_bcs_and_dms();
        bcs.into_iter()
            .map(|(destinations, message)| BCsSupportedMessageOut::BroadcastMessage { destinations, message })
            .chain(
                dms.into_iter()
                    .map(|(destination, message)| BCsSupportedMessageOut::DirectMessage { destination, message }),
            )
    }

    #[cfg(feature = "dev")]
    fn message_out_into_dms(
        message_out: Self::MessageOut,
    ) -> Result<Vec<(SP::Verifier, Message<SP>)>, MessageAttributableError<SP>> {
        match message_out {
            BCsSupportedMessageOut::BroadcastMessage { destinations, message } => Ok(destinations
                .into_iter()
                .map(|destination| (destination, message.clone()))
                .collect()),
            BCsSupportedMessageOut::DirectMessage { destination, message } => Ok([(destination, message)].into()),
            BCsSupportedMessageOut::Error(error) => Err(error),
        }
    }
}

/// A container for outgoing information from a session runner.
#[derive_where::derive_where(Debug)]
pub enum DMsOnlyMessageOut<SP: SessionParameters> {
    /// A direct message that needs to be sent out.
    DirectMessage {
        /// Message destination.
        destination: SP::Verifier,
        /// The message to be sent.
        message: Message<SP>,
    },
    /// A non-fatal problem attributable to message(s) but not to a specific party.
    Error(MessageAttributableError<SP>),
}

impl<SP: SessionParameters> From<MessageAttributableError<SP>> for DMsOnlyMessageOut<SP> {
    fn from(source: MessageAttributableError<SP>) -> Self {
        Self::Error(source)
    }
}

/// A container for outgoing information from a session runner.
#[derive_where::derive_where(Debug)]
pub enum BCsSupportedMessageOut<SP: SessionParameters> {
    /// A direct message that needs to be sent out.
    DirectMessage {
        /// Message destination.
        destination: SP::Verifier,
        /// The message to be sent.
        message: Message<SP>,
    },
    /// A broadcast message that needs to be sent out.
    BroadcastMessage {
        /// Message destinations.
        destinations: BTreeSet<SP::Verifier>,
        /// The message to be sent.
        message: Message<SP>,
    },
    /// A non-fatal problem attributable to message(s) but not to a specific party.
    Error(MessageAttributableError<SP>),
}

impl<SP: SessionParameters> From<MessageAttributableError<SP>> for BCsSupportedMessageOut<SP> {
    fn from(source: MessageAttributableError<SP>) -> Self {
        Self::Error(source)
    }
}
