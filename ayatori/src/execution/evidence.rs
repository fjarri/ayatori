use alloc::{format, string::String, vec::Vec};
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::{
    session::{PreprocessingError, Session},
    session_id::SessionId,
    task::{Task, TaskResultEnum},
};
use crate::{
    entities::{ArrayTag, MessageId, SerializedValue, SignedValue, VerificationError, VerifiedValue},
    errors::LocalError,
    traits::{ExecutableProtocol, SessionParameters},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    session_id: SessionId<SP>,
    guilty_party: SP::Verifier,
    evidence: EvidenceEnum<SP, P>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> Evidence<SP, P> {
    pub(crate) fn new(session_id: &SessionId<SP>, guilty_party: &SP::Verifier, evidence: EvidenceEnum<SP, P>) -> Self {
        Self {
            session_id: session_id.clone(),
            guilty_party: guilty_party.clone(),
            evidence,
        }
    }

    pub fn session_id(&self) -> &SessionId<SP> {
        &self.session_id
    }

    pub fn guilty_party(&self) -> &SP::Verifier {
        &self.guilty_party
    }

    pub fn verify(&self, shared_data: &P::SharedData) -> Result<(), EvidenceError> {
        self.evidence.verify(&self.session_id, &self.guilty_party, shared_data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum EvidenceEnum<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    SenderError(SenderErrorEvidence<SP, P>),
    ConflictingMessages(ConflictingMessagesEvidence<SP>),
    ThirdPartyError(ThirdPartyErrorEvidence<SP, P>),
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> EvidenceEnum<SP, P> {
    pub fn verify(
        &self,
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        shared_data: &P::SharedData,
    ) -> Result<(), EvidenceError> {
        match self {
            Self::SenderError(evidence) => evidence.verify(session_id, guilty_party, shared_data),
            Self::ConflictingMessages(evidence) => evidence.verify(session_id, guilty_party),
            Self::ThirdPartyError(evidence) => evidence.verify(session_id, guilty_party),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ConflictingMessagesEvidence<SP: SessionParameters> {
    first: SignedValue<SP>,
    second: SignedValue<SP>,
}

impl<SP: SessionParameters> ConflictingMessagesEvidence<SP> {
    pub(crate) fn new(first: &VerifiedValue<SP>, second: &VerifiedValue<SP>) -> Self {
        Self {
            first: first.clone().unverify(),
            second: second.clone().unverify(),
        }
    }

    pub fn verify(&self, session_id: &SessionId<SP>, guilty_party: &SP::Verifier) -> Result<(), EvidenceError> {
        if guilty_party != self.first.source() {
            return Err(EvidenceError::new(
                "First message's source does not match `guilty_party`",
            ));
        }

        if guilty_party != self.second.source() {
            return Err(EvidenceError::new(
                "Second message's source does not match `guilty_party`",
            ));
        }

        if self.first.metadata() != self.second.metadata() {
            return Err(EvidenceError::new("Message metadatas differ"));
        }

        if self.first.metadata().session_id() != session_id {
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
pub(crate) struct SenderErrorEvidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    reported_by: SP::Verifier,
    failed_at: ArrayTag,
    signed_values: Vec<SignedValue<SP>>,
    phantom: PhantomData<P>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> SenderErrorEvidence<SP, P> {
    pub fn new(reported_by: &SP::Verifier, failed_at: &ArrayTag, signed_values: Vec<SignedValue<SP>>) -> Self {
        Self {
            reported_by: reported_by.clone(),
            failed_at: failed_at.clone(),
            signed_values,
            phantom: PhantomData,
        }
    }

    pub fn verify(
        &self,
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        shared_data: &P::SharedData,
    ) -> Result<(), EvidenceError> {
        let mut session = Session::<SP, P>::new_with_reproduction_subtree(
            session_id.clone(),
            &self.failed_at,
            &self.reported_by,
            shared_data,
        )?;

        for (idx, signed_value) in self.signed_values.iter().enumerate() {
            if signed_value.source() != guilty_party {
                return Err(EvidenceError::new("The message source is not that of the guilty party"));
            }
            let message_id = MessageId::from_usize(idx);
            let task = session.make_preprocessing_task(&message_id, signed_value.clone());
            let result = task.execute()?;
            session.add_preprocess_result(result)?;
        }

        while let Some(task) = session.make_task()? {
            match task {
                Task::Compute(task) => {
                    let result = task.compute()?;
                    if result.store_in().array() == Some(&self.failed_at)
                        && matches!(result.as_enum(), TaskResultEnum::SenderError { .. })
                    {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ThirdPartyErrorEvidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    failed_at: ArrayTag,
    associated_data: SerializedValue,
    phantom: PhantomData<(SP, P)>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> ThirdPartyErrorEvidence<SP, P> {
    pub fn new(failed_at: &ArrayTag, associated_data: SerializedValue) -> Self {
        Self {
            failed_at: failed_at.clone(),
            associated_data,
            phantom: PhantomData,
        }
    }

    pub fn verify(&self, _session_id: &SessionId<SP>, _guilty_party: &SP::Verifier) -> Result<(), EvidenceError> {
        // TODO (#59): support third party error verification.
        todo!()
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
