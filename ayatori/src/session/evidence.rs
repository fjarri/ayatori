use alloc::{collections::BTreeMap, format, string::String};
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::{
    message::{MessageId, SignedValue, VerificationError, VerifiedValue},
    session::{PreprocessingError, Session},
    session_id::SessionId,
    task::Task,
    task::TaskResultEnum,
};
use crate::error::LocalError;
use crate::protocol::{ExecutableProtocol, FullName, SerializedValue, SessionParameters, Tag};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Evidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    SenderError(SenderErrorEvidence<SP, P>),
    ConflictingMessages(ConflictingMessagesEvidence<SP>),
    ThirdPartyError(ThirdPartyErrorEvidence<SP, P>),
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> Evidence<SP, P> {
    // TODO: make session ID and guilty party common for all evidence objects.
    pub fn guilty_party(&self) -> &SP::Verifier {
        match self {
            Self::SenderError(error) => error.guilty_party(),
            Self::ConflictingMessages(error) => error.guilty_party(),
            Self::ThirdPartyError(error) => error.guilty_party(),
        }
    }

    // TODO: should return some kind of a VerificationResult
    pub fn verify(&self, shared_data: &P::SharedData) -> Result<(), EvidenceError> {
        match self {
            Self::SenderError(evidence) => evidence.verify(shared_data),
            Self::ConflictingMessages(evidence) => evidence.verify(),
            Self::ThirdPartyError(evidence) => evidence.verify(),
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
            return Err(EvidenceError::new(
                "First message's source does not match `guilty_party`",
            ));
        }

        if &self.guilty_party != self.second.source() {
            return Err(EvidenceError::new(
                "Second message's source does not match `guilty_party`",
            ));
        }

        if self.first.metadata() != self.second.metadata() {
            return Err(EvidenceError::new("Message metadatas differ"));
        }

        if self.first.metadata().session_id() != &self.session_id {
            return Err(EvidenceError::new("Message's session ID does not match the one stored"));
        }

        let first_value = self.first.clone().verify_and_unpack()?;
        let second_value = self.second.clone().verify_and_unpack()?;

        if first_value == second_value {
            return Err(EvidenceError::new("Serialized values of both messages are equal"));
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
        let mut session = Session::<SP, P>::new_with_reproduction_subtree(
            self.session_id.clone(),
            &self.failed_at,
            &self.reported_by,
            shared_data,
        )?;

        for (idx, signed_value) in self.signed_values.values().enumerate() {
            let message_id = MessageId::from_usize(idx);
            let task = session.make_preprocessing_task(&message_id, signed_value.clone());
            let result = task.execute()?;
            session.add_preprocess_result(result)?;
        }

        while let Some(task) = session.make_task()? {
            match task {
                Task::Compute(task) => {
                    let store_in = task.store_in().clone();
                    let result = task.compute()?;
                    if store_in == self.failed_at && matches!(result.as_enum(), TaskResultEnum::SenderError { .. }) {
                        return Ok(());
                    }
                    session.add_result(result)?;
                }
                Task::ComputeWithRng(_task) => {
                    return Err(EvidenceError::new(
                        "Unexpected RNG-based computation when reproducing the failure",
                    ));
                }
                Task::Send(task) => {
                    let (_message, result) = task.compute()?;
                    session.add_result(result)?;
                }
                Task::FinalizeWithSuccess(_task) => {
                    return Err(EvidenceError::new("Unexpected finalization with success task"));
                }
                Task::FinalizeWithStall(_task) => {
                    return Err(EvidenceError::new("Unexpected finalization with stall task"));
                }
            }
        }

        Err(EvidenceError::new("The execution did not encounter the expected error"))
    }
}

#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Local error: {0}")]
pub struct EvidenceError(String);

impl EvidenceError {
    /// Creates a new error from anything castable to string.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl From<LocalError> for EvidenceError {
    fn from(source: LocalError) -> Self {
        EvidenceError::new(format!("{source}"))
    }
}

impl From<VerificationError> for EvidenceError {
    fn from(source: VerificationError) -> Self {
        EvidenceError::new(format!("Verification error: {source:?}"))
    }
}

impl<SP: SessionParameters> From<PreprocessingError<SP>> for EvidenceError {
    fn from(source: PreprocessingError<SP>) -> Self {
        EvidenceError::new(format!("Preprocessing error: {source:?}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThirdPartyErrorEvidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    guilty_party: SP::Verifier,
    failed_at: Tag,
    session_id: SessionId<SP>,
    associated_data: SerializedValue,
    phantom: PhantomData<P>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> ThirdPartyErrorEvidence<SP, P> {
    pub(crate) fn new(
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        failed_at: &Tag,
        associated_data: SerializedValue,
    ) -> Self {
        Self {
            session_id: session_id.clone(),
            guilty_party: guilty_party.clone(),
            failed_at: failed_at.clone(),
            associated_data,
            phantom: PhantomData,
        }
    }

    pub fn guilty_party(&self) -> &SP::Verifier {
        &self.guilty_party
    }

    pub fn verify(&self) -> Result<(), EvidenceError> {
        // TODO: support third party error verification.
        todo!()
    }
}
