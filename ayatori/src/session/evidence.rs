use alloc::collections::BTreeMap;
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::{
    message::{MessageId, SignedValue, VerificationError, VerifiedValue},
    session::{PreprocessingError, Session},
    session_id::SessionId,
    task::Task,
};
use crate::error::LocalError;
use crate::protocol::{ExecutableProtocol, FullName, SessionParameters, Tag};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Evidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    SenderError(SenderErrorEvidence<SP, P>),
    ConflictingMessages(ConflictingMessagesEvidence<SP>),
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> Evidence<SP, P> {
    pub fn guilty_party(&self) -> &SP::Verifier {
        match self {
            Self::SenderError(error) => error.guilty_party(),
            Self::ConflictingMessages(error) => error.guilty_party(),
        }
    }

    // TODO: should return some kind of a VerificationResult
    pub fn verify(&self, shared_data: &P::SharedData) -> Result<(), EvidenceError> {
        match self {
            Self::SenderError(evidence) => evidence.verify(shared_data),
            Self::ConflictingMessages(evidence) => evidence.verify(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictingMessagesEvidence<SP: SessionParameters> {
    guilty_party: SP::Verifier,
    session_id: SessionId<SP>,
    first: SignedValue<SP>,
    second: SignedValue<SP>,
}

impl<SP: SessionParameters> ConflictingMessagesEvidence<SP> {
    pub(crate) fn new(
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        first: &VerifiedValue<SP>,
        second: &VerifiedValue<SP>,
    ) -> Self {
        Self {
            session_id: session_id.clone(),
            guilty_party: guilty_party.clone(),
            first: first.clone().unverify(),
            second: second.clone().unverify(),
        }
    }

    pub fn guilty_party(&self) -> &SP::Verifier {
        &self.guilty_party
    }

    pub fn verify(&self) -> Result<(), EvidenceError> {
        if &self.guilty_party != self.first.source() {
            return Err(EvidenceError::InvalidEvidence);
        }

        if &self.guilty_party != self.second.source() {
            return Err(EvidenceError::InvalidEvidence);
        }

        if self.first.metadata() != self.second.metadata() {
            return Err(EvidenceError::InvalidEvidence);
        }

        if self.first.metadata().session_id() != &self.session_id {
            return Err(EvidenceError::InvalidEvidence);
        }

        let first_value = self.first.clone().verify_and_unpack()?;
        let second_value = self.second.clone().verify_and_unpack()?;

        if first_value == second_value {
            return Err(EvidenceError::InvalidEvidence);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderErrorEvidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    guilty_party: SP::Verifier,
    reported_by: SP::Verifier,
    failed_at: Tag,
    session_id: SessionId<SP>,
    // TODO: SignedValue already has its name inside (and signed), we don't need to keep a mapping
    signed_values: BTreeMap<FullName, SignedValue<SP>>,
    phantom: PhantomData<P>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> SenderErrorEvidence<SP, P> {
    pub(crate) fn new(
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        reported_by: &SP::Verifier,
        failed_at: &Tag,
        signed_values: BTreeMap<FullName, SignedValue<SP>>,
    ) -> Self {
        Self {
            session_id: session_id.clone(),
            guilty_party: guilty_party.clone(),
            reported_by: reported_by.clone(),
            failed_at: failed_at.clone(),
            signed_values,
            phantom: PhantomData,
        }
    }

    pub fn guilty_party(&self) -> &SP::Verifier {
        &self.guilty_party
    }

    pub fn verify(&self, shared_data: &P::SharedData) -> Result<(), EvidenceError> {
        let mut session =
            Session::<SP, P>::new_subtree(self.session_id.clone(), &self.failed_at, &self.reported_by, shared_data)
                .map_err(|_err| EvidenceError::InvalidEvidence)?;

        for (idx, signed_value) in self.signed_values.values().enumerate() {
            let message_id = MessageId::from_usize(idx);
            let task = session.make_preprocessing_task(&message_id, signed_value.clone());
            let result = task.execute().map_err(|_err| EvidenceError::InvalidEvidence)?;

            match session.add_preprocess_result(result) {
                Ok(()) => {}
                Err(PreprocessingError::Local(_error)) => return Err(EvidenceError::InvalidEvidence),
                Err(PreprocessingError::InvalidMessage(_error)) => {
                    return Err(EvidenceError::InvalidEvidence);
                }
                Err(PreprocessingError::DuplicateMessages(_error)) => {
                    return Err(EvidenceError::InvalidEvidence);
                }
            };
        }

        while let Some(task) = session.make_task().map_err(|_err| EvidenceError::InvalidEvidence)? {
            match task {
                Task::Compute(task) => {
                    let result = task.compute().map_err(|_err| EvidenceError::InvalidEvidence)?;
                    // TODO: we need to skip evidence generation on error, just get the error back.
                    session
                        .add_result(result)
                        .map_err(|_err| EvidenceError::InvalidEvidence)?;
                }
                Task::ComputeWithRng(_task) => {
                    panic!()
                }
                Task::Send(_task) => {
                    // TODO: generate a fake () value here
                }
                Task::FinalizeWithSuccess(_task) => {
                    panic!()
                }
                Task::FinalizeWithStall(_task) => {
                    panic!()
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum EvidenceError {
    InvalidEvidence,
    Local(LocalError),
}

impl From<VerificationError> for EvidenceError {
    fn from(source: VerificationError) -> Self {
        match source {
            VerificationError::SignatureMismatch => EvidenceError::InvalidEvidence,
            VerificationError::Local(error) => EvidenceError::Local(error),
        }
    }
}
