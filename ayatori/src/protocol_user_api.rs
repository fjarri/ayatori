//! The API to be used by the code that executes the protocol.

pub use crate::{
    entities::{Message, MessageId, PartyGroup, RuntimeError, SessionId, SpuriousError, ThresholdGroup},
    execution::{
        BCsSupportedMessageOut, BroadcastsSupported, DMsOnlyMessageOut, DeterministicTask, DirectMessagesOnly,
        DuplicateMessagesError, Evidence, InvalidMessageError, MessageAttributableError, RandomizedTask,
        ReachedOutputSession, SendTask, Session, SessionOutcome, SessionReport, SessionRunnerConfiguration,
        SessionState, SessionUpdate, Task, UnfinishableOutcome,
    },
    traits::{ExecutableProtocol, SessionParameters},
};

#[cfg(feature = "tokio")]
pub use crate::execution::tokio;
