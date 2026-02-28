use alloc::{format, string::String, sync::Arc, vec};
use core::fmt::Debug;

use signature::rand_core::CryptoRngCore;

use super::message::{Message, MessageId, SignedValue, VerificationError};
use super::session::SessionData;
use crate::{
    error::LocalError,
    protocol::{
        Args, ArrayFunctionError, Erasable, ScalarFunctionError, SessionParameters, Tag, Value, WrappedArrayFunction,
        WrappedArrayFunctionWithRng, WrappedScalarFunction, WrappedScalarFunctionWithRng,
    },
};

#[derive(Debug)]
enum ComputeFunction<SP: SessionParameters> {
    Scalar {
        function: WrappedScalarFunction<SP>,
    },
    Array {
        function: WrappedArrayFunction<SP>,
        id: SP::Verifier,
    },
}

#[derive(Debug)]
pub struct ComputeTask<SP: SessionParameters> {
    store_in: Tag,
    function: ComputeFunction<SP>,
    args: Args<SP>,
}

impl<SP: SessionParameters> ComputeTask<SP> {
    pub fn compute(self) -> Result<TaskResult<SP::Verifier>, LocalError> {
        let store_in = self.store_in.clone();
        match self.function {
            ComputeFunction::Scalar { function } => {
                let result = match function.call(self.args) {
                    Ok(result) => result,
                    Err(ScalarFunctionError::Local(error)) => return Err(error),
                };
                Ok(TaskResult(TaskResultEnum::Compute { store_in, result }))
            }
            ComputeFunction::Array { function, id } => {
                let result = match function.call(&id, self.args) {
                    Ok(result) => result,
                    Err(ArrayFunctionError::Local(error)) => return Err(error),
                    Err(ArrayFunctionError::Sender) => {
                        return Ok(TaskResult(TaskResultEnum::AttributableError { store_in, id }));
                    }
                    Err(ArrayFunctionError::ThirdParty { guilty_party, .. }) => {
                        return Ok(TaskResult(TaskResultEnum::AttributableError {
                            id: guilty_party,
                            store_in,
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
    Scalar {
        function: WrappedScalarFunctionWithRng<SP>,
    },
    Array {
        function: WrappedArrayFunctionWithRng<SP>,
        id: SP::Verifier,
    },
}

#[derive(Debug)]
pub struct ComputeWithRngTask<SP: SessionParameters> {
    store_in: Tag,
    function: ComputeWithRngFunction<SP>,
    args: Args<SP>,
}

impl<SP: SessionParameters> ComputeWithRngTask<SP> {
    pub fn compute(self, rng: &mut impl CryptoRngCore) -> Result<TaskResult<SP::Verifier>, LocalError> {
        let store_in = self.store_in.clone();
        match self.function {
            ComputeWithRngFunction::Scalar { function } => {
                let result = match function.call(rng, self.args) {
                    Ok(result) => result,
                    Err(ScalarFunctionError::Local(error)) => return Err(error),
                };
                Ok(TaskResult(TaskResultEnum::Compute { store_in, result }))
            }
            ComputeWithRngFunction::Array { function, id } => {
                let result = match function.call(rng, &id, self.args) {
                    Ok(result) => result,
                    Err(ArrayFunctionError::Local(error)) => return Err(error),
                    Err(ArrayFunctionError::Sender) => {
                        return Ok(TaskResult(TaskResultEnum::AttributableError { store_in, id }));
                    }
                    Err(ArrayFunctionError::ThirdParty { guilty_party, .. }) => {
                        return Ok(TaskResult(TaskResultEnum::AttributableError {
                            id: guilty_party,
                            store_in,
                        }));
                    }
                };
                Ok(TaskResult(TaskResultEnum::ComputeArray { store_in, id, result }))
            }
        }
    }
}

#[derive(Debug)]
pub struct SendTask<SP: SessionParameters> {
    store_in: Tag,
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

#[derive(Debug)]
pub struct FinalizeTask {
    outcome: Value,
}

impl FinalizeTask {
    pub fn value<T: Clone + Erasable>(self) -> Result<T, LocalError> {
        self.outcome.downcast::<T>()
    }
}

#[derive(Debug)]
pub enum Task<SP: SessionParameters> {
    Send(SendTask<SP>),
    Compute(ComputeTask<SP>),
    ComputeWithRng(ComputeWithRngTask<SP>),
    Finalize(FinalizeTask),
}

impl<SP: SessionParameters> Task<SP> {
    pub(crate) fn finalize(value: Value) -> Self {
        Self::Finalize(FinalizeTask { outcome: value })
    }

    pub(crate) fn send(store_in: Tag, destination: SP::Verifier, signed_value: Value) -> Self {
        Self::Send(SendTask {
            store_in,
            destination,
            signed_value,
        })
    }

    pub(crate) fn compute_scalar(store_in: Tag, function: WrappedScalarFunction<SP>, args: Args<SP>) -> Self {
        Self::Compute(ComputeTask {
            store_in,
            function: ComputeFunction::Scalar { function },
            args,
        })
    }

    pub(crate) fn compute_scalar_with_rng(
        store_in: Tag,
        function: WrappedScalarFunctionWithRng<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask {
            store_in,
            function: ComputeWithRngFunction::Scalar { function },
            args,
        })
    }

    pub(crate) fn compute_array_elem(
        store_in: Tag,
        id: SP::Verifier,
        function: WrappedArrayFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask {
            store_in,
            function: ComputeFunction::Array { id, function },
            args,
        })
    }

    pub(crate) fn compute_array_elem_with_rng(
        store_in: Tag,
        id: SP::Verifier,
        function: WrappedArrayFunctionWithRng<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask {
            store_in,
            function: ComputeWithRngFunction::Array { id, function },
            args,
        })
    }
}

#[derive(Debug)]
pub struct TaskResult<Id>(TaskResultEnum<Id>);

impl<Id> TaskResult<Id> {
    pub(crate) fn into_enum(self) -> TaskResultEnum<Id> {
        self.0
    }
}

#[derive(Debug)]
pub(crate) enum TaskResultEnum<Id> {
    Send { store_in: Tag, destination: Id },
    Compute { store_in: Tag, result: Value },
    ComputeArray { store_in: Tag, id: Id, result: Value },
    AttributableError { store_in: Tag, id: Id },
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

        let source = self.signed_value.source().clone();

        // Check that the value is from one of the session participants.
        // If it isnot, even if we detect something provably wrong with it,
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

        let store_in = Tag::signed_remote_with_full_name(verified_value.metadata().full_name());
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
        store_in: Tag,
        id: SP::Verifier,
        value: Value,
    },
    MessageError {
        message_id: MessageId<SP>,
        description: String,
    },
}
