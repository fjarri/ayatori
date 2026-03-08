use alloc::{collections::BTreeMap, format};
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::{
    message::{MessageId, SignedValue, VerifiedValue},
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

    pub fn verify(&self) -> Result<(), LocalError> {
        todo!()
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

    pub fn verify(&self, shared_data: &P::SharedData) -> Result<(), LocalError> {
        // TODO: some LocalErrors here actually signify invalid evidence, we should distinguish that.
        let mut session =
            Session::<SP, P>::new_subtree(self.session_id.clone(), &self.failed_at, &self.reported_by, shared_data)?;

        for (idx, signed_value) in self.signed_values.values().enumerate() {
            let message_id = MessageId::from_usize(idx);
            let task = session.make_preprocessing_task(&message_id, signed_value.clone());
            let result = task.execute()?;

            // TODO: don't ignore any errors that might happen here
            match session.add_preprocess_result(result) {
                Ok(()) => {}
                Err(PreprocessingError::Local(error)) => return Err(error),
                Err(PreprocessingError::InvalidMessage(error)) => {
                    return Err(LocalError::new(format!("Invalid message: {error:?}")));
                }
                Err(PreprocessingError::DuplicateMessages(error)) => {
                    return Err(LocalError::new(format!("Duplicate messages: {error:?}")));
                }
            };
        }

        while let Some(task) = session.make_task()? {
            match task {
                Task::Compute(task) => {
                    let result = task.compute()?;
                    // TODO: we need to skip evidence generation on error, just get the error back.
                    session.add_result(result)?;
                }
                Task::ComputeWithRng(_task) => {
                    panic!()
                }
                Task::Send(_task) => {
                    // TODO: generate a fake () value here
                }
                Task::FinalizeWithSuccess(_token) => {
                    panic!()
                }
            }
        }

        Ok(())
    }
}
