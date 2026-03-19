use alloc::vec::Vec;
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use signature::rand_core::CryptoRngCore;

use crate::{
    entities::{MessageId, SignedValue},
    traits::SessionParameters,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message<SP: SessionParameters> {
    destination: SP::Verifier,
    values: Vec<SignedValue<SP>>,
}

impl<SP: SessionParameters> Message<SP> {
    pub(crate) fn new(destination: SP::Verifier, values: Vec<SignedValue<SP>>) -> Self {
        Self { destination, values }
    }

    pub fn destination(&self) -> &SP::Verifier {
        &self.destination
    }

    /// Associates a random ID with the message.
    ///
    /// The user is expected to store the ID in association with the message source
    /// (the nature of which will depend on the transport channel used).
    /// If there is a problem with the message that cannot be associated with the specific verifier,
    /// the returned error will contain the ID of the message the information came from.
    /// Then, the user can use whatever measures necessary towards the associated source.
    pub fn attach_id(self, rng: &mut impl CryptoRngCore) -> MessageWithId<SP> {
        let message_id = MessageId::random(rng);
        MessageWithId {
            id: message_id,
            destination: self.destination,
            values: self.values,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageWithId<SP: SessionParameters> {
    id: MessageId<SP>,
    destination: SP::Verifier,
    values: Vec<SignedValue<SP>>,
}

impl<SP: SessionParameters> MessageWithId<SP> {
    pub fn id(&self) -> &MessageId<SP> {
        &self.id
    }

    pub(crate) fn into_values(self) -> impl Iterator<Item = SignedValue<SP>> {
        self.values.into_iter()
    }
}
