use alloc::{format, string::String, sync::Arc, vec};
use core::fmt::Debug;

use signature::rand_core::CryptoRngCore;

use super::message::{Message, MessageId, SignedValue, VerificationError};
use super::{ruleset::OnError, session::SessionData};
use crate::{
    error::LocalError,
    protocol::{
        AnyTagRef, Args, ArrayTag, InfallibleArrayFunction, InfallibleArrayFunctionWithRng,
        InfallibleArrayFunctionWithSigner, InfallibleScalarFunction, InfallibleScalarFunctionWithRng, ScalarTag,
        SenderAttributableArrayFunction, SenderError, SenderErrorEnum, SerializedValue, SessionParameters,
        ThirdPartyAttributableArrayFunction, ThirdPartyError, ThirdPartyErrorEnum, Value,
    },
};

#[derive(Debug)]
enum ComputeFunction<SP: SessionParameters> {
    ScalarInfallible {
        store_in: ScalarTag,
        function: InfallibleScalarFunction<SP>,
    },
    ArrayInfallible {
        store_in: ArrayTag,
        function: InfallibleArrayFunction<SP>,
        id: SP::Verifier,
    },
    ArraySenderAttributable {
        store_in: ArrayTag,
        function: SenderAttributableArrayFunction<SP>,
        id: SP::Verifier,
    },
    ArrayThirdPartyAttributable {
        store_in: ArrayTag,
        function: ThirdPartyAttributableArrayFunction<SP>,
        id: SP::Verifier,
    },
}

#[derive(Debug)]
pub struct ComputeTask<SP: SessionParameters> {
    function: ComputeFunction<SP>,
    args: Args<SP>,
    on_error: OnError,
}

impl<SP: SessionParameters> ComputeTask<SP> {
    pub fn compute(self) -> Result<TaskResult<SP::Verifier>, LocalError> {
        match self.function {
            ComputeFunction::ScalarInfallible { store_in, function } => {
                let result = function.call(self.args)?;
                Ok(TaskResult(TaskResultEnum::Compute { store_in, result }))
            }
            ComputeFunction::ArrayInfallible { store_in, function, id } => {
                let result = function.call(&id, self.args)?;
                Ok(TaskResult(TaskResultEnum::ComputeArray { store_in, id, result }))
            }
            ComputeFunction::ArraySenderAttributable { store_in, function, id } => {
                let result = match function.call(&id, self.args) {
                    Ok(result) => result,
                    Err(SenderError(SenderErrorEnum::Local(error))) => return Err(error),
                    Err(SenderError(SenderErrorEnum::Error)) => {
                        return Ok(TaskResult(TaskResultEnum::SenderError {
                            store_in,
                            id,
                            on_error: self.on_error,
                        }));
                    }
                };
                Ok(TaskResult(TaskResultEnum::ComputeArray { store_in, id, result }))
            }
            ComputeFunction::ArrayThirdPartyAttributable { store_in, function, id } => {
                let result = match function.call(&id, self.args) {
                    Ok(result) => result,
                    Err(ThirdPartyError(ThirdPartyErrorEnum::Local(error))) => return Err(error),
                    Err(ThirdPartyError(ThirdPartyErrorEnum::Error {
                        guilty_party,
                        associated_data,
                    })) => {
                        return Ok(TaskResult(TaskResultEnum::ThirdPartyError {
                            store_in,
                            id: guilty_party,
                            associated_data,
                        }));
                    }
                };
                Ok(TaskResult(TaskResultEnum::ComputeArray { store_in, id, result }))
            }
        }
    }
}

#[derive(Debug)]
enum ComputeWithRngFunction<SP: SessionParameters> {
    ScalarInfallible {
        store_in: ScalarTag,
        function: InfallibleScalarFunctionWithRng<SP>,
    },
    ArrayInfallible {
        store_in: ArrayTag,
        function: InfallibleArrayFunctionWithRng<SP>,
        id: SP::Verifier,
    },
    ArrayInfallibleWithSigner {
        store_in: ArrayTag,
        signer: Arc<SP::Signer>,
        function: InfallibleArrayFunctionWithSigner<SP>,
        id: SP::Verifier,
    },
}

#[derive(Debug)]
pub struct ComputeWithRngTask<SP: SessionParameters> {
    function: ComputeWithRngFunction<SP>,
    args: Args<SP>,
}

impl<SP: SessionParameters> ComputeWithRngTask<SP> {
    pub fn compute(self, rng: &mut impl CryptoRngCore) -> Result<TaskResult<SP::Verifier>, LocalError> {
        match self.function {
            ComputeWithRngFunction::ScalarInfallible { store_in, function } => {
                let result = function.call(rng, self.args)?;
                Ok(TaskResult(TaskResultEnum::Compute { store_in, result }))
            }
            ComputeWithRngFunction::ArrayInfallible { store_in, function, id } => {
                let result = function.call(rng, &id, self.args)?;
                Ok(TaskResult(TaskResultEnum::ComputeArray { store_in, id, result }))
            }
            ComputeWithRngFunction::ArrayInfallibleWithSigner {
                store_in,
                signer,
                function,
                id,
            } => {
                let result = function.call(rng, &signer, &id, self.args)?;
                Ok(TaskResult(TaskResultEnum::ComputeArray { store_in, id, result }))
            }
        }
    }
}

#[derive(Debug)]
pub struct SendTask<SP: SessionParameters> {
    store_in: ArrayTag,
    destination: SP::Verifier,
    signed_value: Value,
}

impl<SP: SessionParameters> SendTask<SP> {
    pub fn compute(self) -> Result<(Message<SP>, TaskResult<SP::Verifier>), LocalError> {
        let signed_value = self.signed_value.downcast::<SignedValue<SP>>()?;
        let signed_values = vec![signed_value];
        let message = Message::new(self.destination.clone(), signed_values);
        let result = TaskResult(TaskResultEnum::Send {
            store_in: self.store_in.clone(),
            destination: self.destination.clone(),
        });
        Ok((message, result))
    }
}

#[derive(Debug, Clone)]
pub struct FinalizeWithSuccessTask(ScalarTag);

impl FinalizeWithSuccessTask {
    pub(crate) fn output_tag(&self) -> &ScalarTag {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct FinalizeWithStallTask(ScalarTag);

impl FinalizeWithStallTask {
    pub(crate) fn stalled_tag(&self) -> &ScalarTag {
        &self.0
    }
}

#[derive(Debug)]
pub enum Task<SP: SessionParameters> {
    Send(SendTask<SP>),
    Compute(ComputeTask<SP>),
    ComputeWithRng(ComputeWithRngTask<SP>),
    FinalizeWithSuccess(FinalizeWithSuccessTask),
    FinalizeWithStall(FinalizeWithStallTask),
}

impl<SP: SessionParameters> Task<SP> {
    pub(crate) fn finalize_with_success(tag: ScalarTag) -> Self {
        Self::FinalizeWithSuccess(FinalizeWithSuccessTask(tag))
    }

    pub(crate) fn finalize_with_stall(tag: ScalarTag) -> Self {
        Self::FinalizeWithStall(FinalizeWithStallTask(tag))
    }

    pub(crate) fn send(store_in: ArrayTag, destination: SP::Verifier, signed_value: Value) -> Self {
        Self::Send(SendTask {
            store_in,
            destination,
            signed_value,
        })
    }

    pub(crate) fn compute_scalar_infallible(
        store_in: ScalarTag,
        function: InfallibleScalarFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask {
            function: ComputeFunction::ScalarInfallible { store_in, function },
            args,
            on_error: OnError::Escalate,
        })
    }

    pub(crate) fn compute_scalar_infallible_with_rng(
        store_in: ScalarTag,
        function: InfallibleScalarFunctionWithRng<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask {
            function: ComputeWithRngFunction::ScalarInfallible { store_in, function },
            args,
        })
    }

    pub(crate) fn compute_array_elem_infallible(
        store_in: ArrayTag,
        id: SP::Verifier,
        function: InfallibleArrayFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask {
            function: ComputeFunction::ArrayInfallible { store_in, id, function },
            args,
            on_error: OnError::Escalate,
        })
    }

    pub(crate) fn compute_array_elem_infallible_with_rng(
        store_in: ArrayTag,
        id: SP::Verifier,
        function: InfallibleArrayFunctionWithRng<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask {
            function: ComputeWithRngFunction::ArrayInfallible { store_in, id, function },
            args,
        })
    }

    pub(crate) fn compute_array_elem_infallible_with_signer(
        store_in: ArrayTag,
        signer: &Arc<SP::Signer>,
        id: SP::Verifier,
        function: InfallibleArrayFunctionWithSigner<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask {
            function: ComputeWithRngFunction::ArrayInfallibleWithSigner {
                store_in,
                signer: signer.clone(),
                id,
                function,
            },
            args,
        })
    }

    pub(crate) fn compute_array_elem_sender_attributable(
        store_in: ArrayTag,
        id: SP::Verifier,
        function: SenderAttributableArrayFunction<SP>,
        args: Args<SP>,
        on_error: OnError,
    ) -> Self {
        Self::Compute(ComputeTask {
            function: ComputeFunction::ArraySenderAttributable { store_in, id, function },
            args,
            on_error,
        })
    }

    pub(crate) fn compute_array_elem_third_party_attributable(
        store_in: ArrayTag,
        id: SP::Verifier,
        function: ThirdPartyAttributableArrayFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask {
            function: ComputeFunction::ArrayThirdPartyAttributable { store_in, id, function },
            args,
            // TODO (#59): support third party attributable failures
            on_error: OnError::Escalate,
        })
    }
}

#[derive(Debug)]
pub struct TaskResult<Id>(TaskResultEnum<Id>);

impl<Id> TaskResult<Id> {
    pub(crate) fn as_enum(&self) -> &TaskResultEnum<Id> {
        &self.0
    }

    pub(crate) fn into_enum(self) -> TaskResultEnum<Id> {
        self.0
    }

    pub(crate) fn store_in(&self) -> AnyTagRef<'_> {
        match &self.0 {
            TaskResultEnum::Compute { store_in, .. } => AnyTagRef::Scalar(store_in),
            TaskResultEnum::Send { store_in, .. }
            | TaskResultEnum::ComputeArray { store_in, .. }
            | TaskResultEnum::SenderError { store_in, .. }
            | TaskResultEnum::ThirdPartyError { store_in, .. } => AnyTagRef::Array(store_in),
        }
    }
}

#[derive(Debug)]
pub(crate) enum TaskResultEnum<Id> {
    Send {
        store_in: ArrayTag,
        destination: Id,
    },
    Compute {
        store_in: ScalarTag,
        result: Value,
    },
    ComputeArray {
        store_in: ArrayTag,
        id: Id,
        result: Value,
    },
    SenderError {
        store_in: ArrayTag,
        id: Id,
        on_error: OnError,
    },
    ThirdPartyError {
        store_in: ArrayTag,
        id: Id,
        associated_data: SerializedValue,
    },
}

#[derive(Debug)]
pub struct PreprocessingTask<SP: SessionParameters> {
    session_data: Arc<SessionData<SP>>,
    message_id: MessageId<SP>,
    signed_value: SignedValue<SP>,
}

impl<SP: SessionParameters> PreprocessingTask<SP> {
    pub(crate) fn new(
        session_data: &Arc<SessionData<SP>>,
        message_id: MessageId<SP>,
        signed_value: SignedValue<SP>,
    ) -> Self {
        Self {
            session_data: session_data.clone(),
            message_id,
            signed_value,
        }
    }

    pub fn execute(self) -> Result<PreprocessingResult<SP>, LocalError> {
        // Before storing the value in the database, we check for the failures that are unattributable at this level.
        // In case of a failure all we can do is report the message ID and let the user deal with it
        // if their transport protocol allows it.

        // TODO (#60): reject messages from already banned nodes

        let source = self.signed_value.source().clone();

        // Check that the value is from one of the session participants.
        // If it is not, even if we detect something provably wrong with it,
        // the proof will be useless.
        if !self.session_data.participants.contains(self.signed_value.source()) {
            return Ok(PreprocessingResult(PreprocessingResultEnum::MessageError {
                message_id: self.message_id,
                description: format!("A sender {source:?} is not one of the participants"),
            }));
        }

        // Check that the message is addressed to a correct destination (one that this node manages).
        // If it is not, it may be a replay attack.
        if !self
            .session_data
            .local_participants
            .contains(self.signed_value.metadata().destination())
        {
            return Ok(PreprocessingResult(PreprocessingResultEnum::MessageError {
                message_id: self.message_id,
                description: format!(
                    "A destination {:?} is not one of the local participants",
                    self.signed_value.metadata().destination()
                ),
            }));
        }

        // Check that the value belongs to the this session.
        // If it does not, it may be a replay attack.
        if self.signed_value.metadata().session_id() != &self.session_data.id {
            return Ok(PreprocessingResult(PreprocessingResultEnum::MessageError {
                message_id: self.message_id,
                description: "Invalid session ID".into(),
            }));
        }

        // Verify the value signature.
        let verified_value = match self.signed_value.verify(&self.message_id) {
            Ok(value) => value,
            Err(VerificationError::Local(error)) => return Err(error),
            Err(VerificationError::SignatureMismatch) => {
                return Ok(PreprocessingResult(PreprocessingResultEnum::MessageError {
                    message_id: self.message_id.clone(),
                    description: format!("Verification error for a message from {source:?}"),
                }));
            }
        };

        let store_in = ArrayTag::signed_remote_with_full_name(verified_value.metadata().full_name());
        let value = Value::new(verified_value);

        Ok(PreprocessingResult(PreprocessingResultEnum::Success {
            store_in,
            id: source,
            value,
        }))
    }
}

#[derive(Debug)]
pub struct PreprocessingResult<SP: SessionParameters>(PreprocessingResultEnum<SP>);

impl<SP: SessionParameters> PreprocessingResult<SP> {
    pub(crate) fn into_enum(self) -> PreprocessingResultEnum<SP> {
        self.0
    }
}

#[derive(Debug)]
pub(crate) enum PreprocessingResultEnum<SP: SessionParameters> {
    Success {
        store_in: ArrayTag,
        id: SP::Verifier,
        value: Value,
    },
    MessageError {
        message_id: MessageId<SP>,
        description: String,
    },
}
