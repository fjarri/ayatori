//! The API to be used by the code that executes the protocol.

pub use crate::{
    entities::{Message, MessageId, PartyGroup, RuntimeError, SessionId, SpuriousError},
    execution::{
        DuplicateMessagesError, Evidence, InvalidMessageError, MessageAttributableError, ReachedOutputSession, Session,
        SessionOutcome, SessionReport, SessionState, Task,
    },
    traits::{ExecutableProtocol, SessionParameters},
};

#[cfg(feature = "tokio")]
pub use crate::execution::tokio;
