use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::message::{SignedValue, VerifiedValue};
use crate::error::LocalError;
use crate::protocol::{SessionParameters, Tag};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Evidence<SP: SessionParameters> {
    SenderError(SenderErrorEvidence<SP>),
    ConflictingMessages(ConflictingMessagesEvidence<SP>),
}

impl<SP: SessionParameters> Evidence<SP> {
    pub fn guilty_party(&self) -> &SP::Verifier {
        match self {
            Self::SenderError(error) => error.guilty_party(),
            Self::ConflictingMessages(error) => error.guilty_party(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictingMessagesEvidence<SP: SessionParameters> {
    guilty_party: SP::Verifier,
    first: SignedValue<SP>,
    second: SignedValue<SP>,
}

impl<SP: SessionParameters> ConflictingMessagesEvidence<SP> {
    pub(crate) fn new(guilty_party: &SP::Verifier, first: &VerifiedValue<SP>, second: &VerifiedValue<SP>) -> Self {
        Self {
            guilty_party: guilty_party.clone(),
            first: first.clone().unverify(),
            second: second.clone().unverify(),
        }
    }

    pub fn guilty_party(&self) -> &SP::Verifier {
        &self.guilty_party
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderErrorEvidence<SP: SessionParameters> {
    guilty_party: SP::Verifier,
    failed_at: Tag,
    signed_values: BTreeMap<Tag, SignedValue<SP>>,
}

impl<SP: SessionParameters> SenderErrorEvidence<SP> {
    pub(crate) fn new(
        guilty_party: &SP::Verifier,
        failed_at: &Tag,
        signed_values: BTreeMap<Tag, SignedValue<SP>>,
    ) -> Self {
        Self {
            guilty_party: guilty_party.clone(),
            failed_at: failed_at.clone(),
            signed_values,
        }
    }

    pub fn guilty_party(&self) -> &SP::Verifier {
        &self.guilty_party
    }

    pub fn verify(&self) -> Result<(), LocalError> {
        todo!()
    }
}
