//! The API to be used by the code that executes the protocol.

pub use crate::{
    entities::{Message, MessageId, PartyGroup, RuntimeError, SessionId, SpuriousError},
    execution::{
        DeterministicTask, DuplicateMessagesError, Evidence, InvalidMessageError, MessageAttributableError,
        RandomizedTask, ReachedOutputSession, SendTask, SendTaskResult, Session, SessionOutcome, SessionReport,
        SessionState, SessionUpdate, Task, UnfinishableOutcome,
    },
    traits::{ExecutableProtocol, SessionParameters},
};

#[cfg(feature = "tokio")]
pub use crate::execution::tokio;
