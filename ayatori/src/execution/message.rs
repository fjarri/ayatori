// TODO: move the whole thing to `entities`?

use alloc::vec::Vec;
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{entities::SignedValue, traits::SessionParameters};

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

    pub(crate) fn into_values(self) -> impl Iterator<Item = SignedValue<SP>> {
        self.values.into_iter()
    }
}
