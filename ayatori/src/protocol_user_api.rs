//! The API to be used by the code that executes the protocol.

pub use crate::{
    entities::{Message, MessageId, PartyGroup, RuntimeError, SessionId, UnattributableError},
    execution::{
        DuplicateMessagesError, Evidence, InvalidMessageError, MessageAttributableError, ReachedOutputSession, Session,
        SessionReport, SessionState, StalledSession, Task, TaskError,
    },
    traits::{ExecutableProtocol, SessionParameters},
};

#[cfg(feature = "tokio")]
pub use crate::execution::tokio;
