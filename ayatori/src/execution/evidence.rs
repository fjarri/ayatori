use alloc::{format, string::String, vec::Vec};
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::{session::Session, session_id::SessionId, task::Task};
use crate::{
    entities::{
        AnyTagRef, AssociatedData, EvidenceVerdict, MappingFunction, MappingTag, Message, MessageId, SignedValue,
        VerificationError, VerifiedValue,
    },
    errors::LocalError,
    graph_representation::{ArgNodes, NodeKind, PartyBuildData},
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
    SenderErrorWithInfo(SenderErrorEvidenceWithInfo<SP, P>),
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
            Self::SenderErrorWithInfo(evidence) => evidence.verify(session_id, guilty_party, shared_data),
            Self::ConflictingMessages(evidence) => evidence.verify(session_id, guilty_party),
            Self::ThirdPartyError(evidence) => evidence.verify(session_id, guilty_party, shared_data),
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
    failed_at: MappingTag,
    signed_values: Vec<SignedValue<SP>>,
    phantom: PhantomData<P>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> SenderErrorEvidence<SP, P> {
    pub fn new(reported_by: &SP::Verifier, failed_at: &MappingTag, signed_values: Vec<SignedValue<SP>>) -> Self {
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
        let session = Session::<SP, P>::new_with_reproduction_subtree(
            session_id.clone(),
            &self.failed_at,
            &self.reported_by,
            guilty_party,
            shared_data,
            None,
        )?;

        run_evidence_verification_session(session, &self.reported_by, guilty_party, &self.signed_values)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SenderErrorEvidenceWithInfo<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    reported_by: SP::Verifier,
    failed_at: MappingTag,
    signed_values: Vec<SignedValue<SP>>,
    associated_data: AssociatedData<SP>,
    phantom: PhantomData<P>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> SenderErrorEvidenceWithInfo<SP, P> {
    pub fn new(
        reported_by: &SP::Verifier,
        failed_at: &MappingTag,
        signed_values: Vec<SignedValue<SP>>,
        associated_data: AssociatedData<SP>,
    ) -> Self {
        Self {
            reported_by: reported_by.clone(),
            failed_at: failed_at.clone(),
            signed_values,
            associated_data,
            phantom: PhantomData,
        }
    }

    pub fn verify(
        &self,
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        shared_data: &P::SharedData,
    ) -> Result<(), EvidenceError> {
        let session = Session::<SP, P>::new_with_reproduction_subtree(
            session_id.clone(),
            &self.failed_at,
            &self.reported_by,
            guilty_party,
            shared_data,
            Some(&self.associated_data),
        )?;

        run_evidence_verification_session(session, &self.reported_by, guilty_party, &self.signed_values)
    }
}

fn run_evidence_verification_session<SP: SessionParameters, P: ExecutableProtocol<SP>>(
    mut session: Session<SP, P>,
    session_verifier: &SP::Verifier,
    guilty_party: &SP::Verifier,
    signed_values: &[SignedValue<SP>],
) -> Result<(), EvidenceError> {
    for signed_value in signed_values.iter() {
        if signed_value.source() != guilty_party {
            return Err(EvidenceError::new("The message source is not that of the guilty party"));
        }
    }

    let message_id = MessageId::from_usize(0);
    session.add_message(
        &message_id,
        Message::new(session_verifier.clone(), signed_values.to_vec()),
    );

    while let Some(task) = session.make_task()? {
        let task_result = match task {
            Task::Compute(task) => {
                let result = task.compute()?;
                session.add_result(result)
            }
            Task::ComputeWithRng(_task) => {
                return Err(EvidenceError::new(
                    "Unexpected RNG-based computation when reproducing the failure",
                ));
            }
            Task::Send(task) => {
                let (_message, result) = task.compute()?;
                session.add_result(result)
            }
            Task::FinalizeWithSuccess(task) => {
                let verdict = session.finalize_with_evidence_verdict(task)?;
                return match verdict {
                    EvidenceVerdict::Valid => Ok(()),
                    EvidenceVerdict::Invalid(error) => Err(EvidenceError::new(format!("Invalid evidence: {error}"))),
                };
            }
            Task::FinalizeWithStall(_task) => {
                return Err(EvidenceError::new("Unexpected finalization with stall task"));
            }
        };

        if let Some(error) = task_result.err() {
            return Err(EvidenceError::new(format!("Unexpected task error: {error:?}")));
        }
    }

    Err(EvidenceError::new("The execution did not encounter the expected error"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ThirdPartyErrorEvidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    reported_by: SP::Verifier,
    failed_at: MappingTag,
    associated_data: AssociatedData<SP>,
    phantom: PhantomData<(SP, P)>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> ThirdPartyErrorEvidence<SP, P> {
    pub fn new(reported_by: &SP::Verifier, failed_at: &MappingTag, associated_data: AssociatedData<SP>) -> Self {
        Self {
            reported_by: reported_by.clone(),
            failed_at: failed_at.clone(),
            associated_data,
            phantom: PhantomData,
        }
    }

    pub fn verify(
        &self,
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        shared_data: &P::SharedData,
    ) -> Result<(), EvidenceError> {
        let build_data = P::make_build_data(shared_data);
        let signature = P::signature();
        let arg_nodes = ArgNodes::new(&signature);
        let party_build_data = PartyBuildData::new(&self.reported_by);
        let output = P::build(&party_build_data, &build_data, arg_nodes)?;
        let node = output
            .find_subnode(AnyTagRef::Mapping(self.failed_at.as_ref()))
            .ok_or_else(|| EvidenceError::new(format!("Could not find subnode {}", self.failed_at)))?;

        let function = match node.kind() {
            NodeKind::ComputeMapping { function, .. } => function,
            _ => return Err(EvidenceError::new("Invalid node type")),
        };

        let verification = match function {
            MappingFunction::ThirdPartyAttributable { verification, .. } => verification,
            _ => return Err(EvidenceError::new("Invalid function type")),
        };

        let verdict = verification.call(guilty_party, session_id, &self.associated_data)?;
        match verdict {
            EvidenceVerdict::Valid => Ok(()),
            EvidenceVerdict::Invalid(error) => Err(EvidenceError::new(format!("Invalid evidence: {error}"))),
        }
    }
}

#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Evidence error: {0}")]
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
