use alloc::collections::BTreeMap;
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::message::{SignedValue, VerifiedValue};
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
    signed_values: BTreeMap<FullName, SignedValue<SP>>,
    phantom: PhantomData<P>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> SenderErrorEvidence<SP, P> {
    pub(crate) fn new(
        guilty_party: &SP::Verifier,
        reported_by: &SP::Verifier,
        failed_at: &Tag,
        signed_values: BTreeMap<FullName, SignedValue<SP>>,
    ) -> Self {
        Self {
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

    pub fn verify(&self, _shared_data: &P::SharedData) -> Result<(), LocalError> {
        /*
        let build_data = P::make_build_data(shared_data);
        let signature = P::signature();
        let arg_nodes = ArgNodes::new(&signature);
        let output_node = P::build(&self.reported_by, &build_data, arg_nodes)?;

        let output_node = output_node.get_subtree(&self.failed_at)?;

        let private_inputs = PrivateInputs::new();
        let public_inputs = P::make_public_inputs(shared_data);

        let ruleset = Ruleset::new(&output_node, &private_inputs)?;
        let storage = Storage::new(public_inputs, private_inputs);

        //let state = State::new(ruleset, storage);
        */
        Ok(())
    }
}
