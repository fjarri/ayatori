//! The API to be used by the code that executes the protocol.

pub use crate::{
    entities::{Message, MessageId, PartyGroup, SessionId},
    execution::{Evidence, Session, SessionReport, Task, TaskError},
    traits::SessionParameters,
};
