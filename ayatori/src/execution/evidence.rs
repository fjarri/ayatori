use alloc::{format, vec::Vec};
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::{session::Session, task::Task};
use crate::{
    entities::{
        AnyTagRef, EvidenceVerdict, MappingTag, Message, MessageId, RuntimeError, SenderError, SenderErrorWithReveal,
        SessionId, SignedValue, ThirdPartyError, UnattributableError, VerificationError, VerifiedValue,
    },
    graph_representation::{AnyNode, ArgNodes, ComputeMappingKind, PartyBuildData},
    traits::{ExecutableProtocol, SessionParameters},
};

/// Evidence of malicious behavior of a protocol participant,
/// verifiable by anyone having access to the shared public data used during the protocol's execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    session_id: SessionId<SP>,
    guilty_party: SP::Verifier,
    kind: EvidenceKind<SP, P>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> Evidence<SP, P> {
    pub(crate) fn new(session_id: &SessionId<SP>, guilty_party: &SP::Verifier, kind: EvidenceKind<SP, P>) -> Self {
        Self {
            session_id: session_id.clone(),
            guilty_party: guilty_party.clone(),
            kind,
        }
    }

    /// Returns the ID of the session where the evidence was recorded.
    pub fn session_id(&self) -> &SessionId<SP> {
        &self.session_id
    }

    /// Returns the ID of the guilty party.
    pub fn guilty_party(&self) -> &SP::Verifier {
        &self.guilty_party
    }

    /// Verifies the evidence given the same public shared data used for the protocol execution.
    pub fn verify(&self, shared_data: &P::SharedData) -> Result<EvidenceVerdict, RuntimeError> {
        self.kind.verify(&self.session_id, &self.guilty_party, shared_data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum EvidenceKind<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    SenderError(SenderErrorEvidence<SP, P>),
    SenderErrorWithReveal(SenderErrorWithRevealEvidence<SP, P>),
    ConflictingMessages(ConflictingMessagesEvidence<SP>),
    ThirdPartyError(ThirdPartyErrorEvidence<SP, P>),
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> EvidenceKind<SP, P> {
    pub fn verify(
        &self,
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        shared_data: &P::SharedData,
    ) -> Result<EvidenceVerdict, RuntimeError> {
        match self {
            Self::SenderError(evidence) => evidence.verify(session_id, guilty_party, shared_data),
            Self::SenderErrorWithReveal(evidence) => evidence.verify(session_id, guilty_party, shared_data),
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

    pub fn verify(
        &self,
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
    ) -> Result<EvidenceVerdict, RuntimeError> {
        if guilty_party != self.first.source() {
            return Ok(EvidenceVerdict::invalid(
                "First message's source does not match `guilty_party`",
            ));
        }

        if guilty_party != self.second.source() {
            return Ok(EvidenceVerdict::invalid(
                "Second message's source does not match `guilty_party`",
            ));
        }

        if self.first.metadata() != self.second.metadata() {
            return Ok(EvidenceVerdict::invalid("Message metadatas differ"));
        }

        if self.first.metadata().session_id() != session_id {
            return Ok(EvidenceVerdict::invalid(
                "Message's session ID does not match the one stored",
            ));
        }

        let first_value = match self.first.clone().verify_and_unpack() {
            Ok(value) => value,
            Err(VerificationError::SignatureMismatch) => {
                return Ok(EvidenceVerdict::invalid("Failed to verify the first value"));
            }
            Err(VerificationError::Runtime(error)) => return Err(error),
        };
        let second_value = match self.second.clone().verify_and_unpack() {
            Ok(value) => value,
            Err(VerificationError::SignatureMismatch) => {
                return Ok(EvidenceVerdict::invalid("Failed to verify the second value"));
            }
            Err(VerificationError::Runtime(error)) => return Err(error),
        };

        if first_value == second_value {
            return Ok(EvidenceVerdict::invalid("Serialized values of both messages are equal"));
        }

        Ok(EvidenceVerdict::valid())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SenderErrorEvidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    reported_by: SP::Verifier,
    failed_at: MappingTag,
    signed_values: Vec<SignedValue<SP>>,
    error: SenderError,
    phantom: PhantomData<P>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> SenderErrorEvidence<SP, P> {
    pub fn new(
        reported_by: &SP::Verifier,
        failed_at: &MappingTag,
        signed_values: Vec<SignedValue<SP>>,
        error: SenderError,
    ) -> Self {
        Self {
            reported_by: reported_by.clone(),
            failed_at: failed_at.clone(),
            signed_values,
            error,
            phantom: PhantomData,
        }
    }

    pub fn verify(
        &self,
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        shared_data: &P::SharedData,
    ) -> Result<EvidenceVerdict, RuntimeError> {
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
pub(crate) struct SenderErrorWithRevealEvidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    reported_by: SP::Verifier,
    failed_at: MappingTag,
    signed_values: Vec<SignedValue<SP>>,
    error: SenderErrorWithReveal<SP>,
    phantom: PhantomData<P>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> SenderErrorWithRevealEvidence<SP, P> {
    pub fn new(
        reported_by: &SP::Verifier,
        failed_at: &MappingTag,
        signed_values: Vec<SignedValue<SP>>,
        error: SenderErrorWithReveal<SP>,
    ) -> Self {
        Self {
            reported_by: reported_by.clone(),
            failed_at: failed_at.clone(),
            signed_values,
            error,
            phantom: PhantomData,
        }
    }

    pub fn verify(
        &self,
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        shared_data: &P::SharedData,
    ) -> Result<EvidenceVerdict, RuntimeError> {
        let session = Session::<SP, P>::new_with_reproduction_subtree(
            session_id.clone(),
            &self.failed_at,
            &self.reported_by,
            guilty_party,
            shared_data,
            Some(&self.error.associated_data),
        )?;

        run_evidence_verification_session(session, &self.reported_by, guilty_party, &self.signed_values)
    }
}

fn run_evidence_verification_session<SP: SessionParameters, P: ExecutableProtocol<SP>>(
    mut session: Session<SP, P>,
    session_verifier: &SP::Verifier,
    guilty_party: &SP::Verifier,
    signed_values: &[SignedValue<SP>],
) -> Result<EvidenceVerdict, RuntimeError> {
    for signed_value in signed_values {
        if signed_value.source() != guilty_party {
            return Ok(EvidenceVerdict::invalid(
                "The message source is not that of the guilty party",
            ));
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
                let result = match task.compute() {
                    Ok(result) => result,
                    Err(UnattributableError::Spurious(error)) => {
                        return Ok(EvidenceVerdict::invalid(format!(
                            "Unexpected spurious error when reproducing the failure: {error}"
                        )));
                    }
                    Err(UnattributableError::Runtime(error)) => return Err(error),
                };
                session.add_result(result)
            }
            Task::ComputeWithRng(_task) => {
                return Ok(EvidenceVerdict::invalid(
                    "Unexpected RNG-based computation when reproducing the failure",
                ));
            }
            Task::Send(task) => {
                let (_message, result) = match task.compute() {
                    Ok(result) => result,
                    Err(UnattributableError::Spurious(error)) => {
                        return Ok(EvidenceVerdict::invalid(format!(
                            "Unexpected spurious error when reproducing the failure: {error}"
                        )));
                    }
                    Err(UnattributableError::Runtime(error)) => return Err(error),
                };
                session.add_result(result)
            }
            Task::FinalizeWithSuccess(task) => {
                return session.finalize_with_evidence_verdict(task);
            }
            Task::FinalizeWithStalled(_task) => {
                return Ok(EvidenceVerdict::invalid("Unexpected finalization with stall task"));
            }
        };

        if let Some(error) = task_result.err() {
            return Ok(EvidenceVerdict::invalid(format!("Unexpected task error: {error:?}")));
        }
    }

    Ok(EvidenceVerdict::invalid(
        "The execution did not encounter the expected error",
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ThirdPartyErrorEvidence<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    reported_by: SP::Verifier,
    failed_at: MappingTag,
    error: ThirdPartyError<SP>,
    phantom: PhantomData<(SP, P)>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> ThirdPartyErrorEvidence<SP, P> {
    pub fn new(reported_by: &SP::Verifier, failed_at: &MappingTag, error: ThirdPartyError<SP>) -> Self {
        Self {
            reported_by: reported_by.clone(),
            failed_at: failed_at.clone(),
            error,
            phantom: PhantomData,
        }
    }

    pub fn verify(
        &self,
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        shared_data: &P::SharedData,
    ) -> Result<EvidenceVerdict, RuntimeError> {
        let build_data = P::make_build_data(shared_data);
        let signature = P::signature();
        let arg_nodes = ArgNodes::new(&signature);
        let party_build_data = PartyBuildData::new(&self.reported_by);
        let output = P::build(&party_build_data, &build_data, arg_nodes)?;
        let any_node = Into::<AnyNode<SP>>::into(output);
        let Some(node) = any_node.find_subnode(AnyTagRef::Mapping(self.failed_at.as_ref())) else {
            return Ok(EvidenceVerdict::invalid(format!(
                "Could not find subnode {}",
                self.failed_at
            )));
        };

        let AnyNode::ComputeMapping(node) = node else {
            return Ok(EvidenceVerdict::invalid("Invalid node type"));
        };

        let ComputeMappingKind::ThirdPartyAttributable { verification, .. } = &node.as_ref().kind else {
            return Ok(EvidenceVerdict::invalid("Invalid function type"));
        };

        verification.call(guilty_party, session_id, &self.error.associated_data)
    }
}
