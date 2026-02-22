use alloc::{format, string::String, sync::Arc, vec, vec::Vec};
use core::fmt::Debug;

use signature::rand_core::CryptoRngCore;

use super::message::{Message, MessageId, MessageWithId, SignedValue, VerificationError};
use super::session::SessionData;
use crate::{
    error::LocalError,
    protocol::{
        Args, ComputeError, ComputeErrorEnum, Erasable, SessionParameters, Tag, Value, WrappedArrayFunction,
        WrappedArrayFunctionPrivate, WrappedScalarFunction, WrappedScalarFunctionPrivate,
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
                    Err(ComputeError(ComputeErrorEnum::Local(error))) => return Err(error),
                    Err(ComputeError(ComputeErrorEnum::Data)) => {
                        return Ok(TaskResult(TaskResultEnum::UnattributableError { store_in }));
                    }
                    Err(ComputeError(ComputeErrorEnum::ThirdParty { guilty_party, .. })) => {
                        return Ok(TaskResult(TaskResultEnum::AttributableError {
                            id: guilty_party,
                            store_in,
                        }));
                    }
                };
                Ok(TaskResult(TaskResultEnum::Compute { store_in, result }))
            }
            ComputeFunction::Array { function, id } => {
                let result = match function.call(&id, self.args) {
                    Ok(result) => result,
                    Err(ComputeError(ComputeErrorEnum::Local(error))) => return Err(error),
                    Err(ComputeError(ComputeErrorEnum::Data)) => {
                        return Ok(TaskResult(TaskResultEnum::AttributableError { store_in, id }));
                    }
                    Err(ComputeError(ComputeErrorEnum::ThirdParty { guilty_party, .. })) => {
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
        function: WrappedScalarFunctionPrivate<SP>,
    },
    Array {
        function: WrappedArrayFunctionPrivate<SP>,
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
                    Err(ComputeError(ComputeErrorEnum::Local(error))) => return Err(error),
                    Err(ComputeError(ComputeErrorEnum::Data)) => {
                        return Ok(TaskResult(TaskResultEnum::UnattributableError { store_in }));
                    }
                    Err(ComputeError(ComputeErrorEnum::ThirdParty { guilty_party, .. })) => {
                        return Ok(TaskResult(TaskResultEnum::AttributableError {
                            id: guilty_party,
                            store_in,
                        }));
                    }
                };
                Ok(TaskResult(TaskResultEnum::Compute { store_in, result }))
            }
            ComputeWithRngFunction::Array { function, id } => {
                let result = match function.call(rng, &id, self.args) {
                    Ok(result) => result,
                    Err(ComputeError(ComputeErrorEnum::Local(error))) => return Err(error),
                    Err(ComputeError(ComputeErrorEnum::Data)) => {
                        return Ok(TaskResult(TaskResultEnum::AttributableError { store_in, id }));
                    }
                    Err(ComputeError(ComputeErrorEnum::ThirdParty { guilty_party, .. })) => {
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
        function: WrappedScalarFunctionPrivate<SP>,
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
        function: WrappedArrayFunctionPrivate<SP>,
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
    UnattributableError { store_in: Tag },
    AttributableError { store_in: Tag, id: Id },
}

#[derive(Debug)]
pub struct PreprocessingTask<SP: SessionParameters> {
    message: MessageWithId<SP>,
    session_data: Arc<SessionData<SP>>,
}

impl<SP: SessionParameters> PreprocessingTask<SP> {
    pub(crate) fn new(message: MessageWithId<SP>, session_data: &Arc<SessionData<SP>>) -> Self {
        Self {
            message,
            session_data: session_data.clone(),
        }
    }

    pub fn execute(self) -> Result<PreprocessingResult<SP>, LocalError> {
        // Before storing the message in the database, we check for the failures that are unattributable at this level.
        // In case of a failure all we can do is report the message ID and let the user deal with it
        // if their transport protocol allows it.

        let message_id = self.message.id().clone();

        // Check if all the messages are from the session participants.
        // If they are not, even if we detect something provably wrong with them,
        // the proof will be useless.
        for source in self.message.sources() {
            if !self.session_data.participants.contains(source) {
                return Ok(PreprocessingResult(PreprocessingResultEnum::MessageError {
                    message_id,
                    description: format!("A sender {source:?} is not one of the participants"),
                }));
            }
        }

        // Check that the messages are sent to correct destinations (the ones this node manages).
        // If they are not, it may be a replay attack.
        if !self
            .session_data
            .local_participants
            .contains(self.message.destination())
        {
            return Ok(PreprocessingResult(PreprocessingResultEnum::MessageError {
                message_id,
                description: format!(
                    "A destination {:?} is not one of the local participants",
                    self.message.destination()
                ),
            }));
        }

        // Check that the messages belong to the this session.
        // If they are not, it may be a replay attack.
        for value in self.message.values() {
            if value.metadata().session_id() != &self.session_data.id {
                return Ok(PreprocessingResult(PreprocessingResultEnum::MessageError {
                    message_id,
                    description: "Invalid session ID".into(),
                }));
            }
        }

        let mut verified_values = Vec::new();

        // Verify the value signatures.
        for value in self.message.into_values() {
            let source = value.source().clone();
            let verified_value = match value.verify(&message_id) {
                Ok(value) => value,
                Err(VerificationError::Local(error)) => return Err(error),
                Err(VerificationError::SignatureMismatch) => {
                    return Ok(PreprocessingResult(PreprocessingResultEnum::MessageError {
                        message_id: message_id.clone(),
                        description: format!("Verification error for a message from {source:?}"),
                    }));
                }
            };

            let tag = Tag::signed_remote(verified_value.metadata().full_name());
            verified_values.push((tag, source, Value::new(verified_value)));
        }

        Ok(PreprocessingResult(PreprocessingResultEnum::Success {
            to_store: verified_values,
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
        to_store: Vec<(Tag, SP::Verifier, Value)>,
    },
    MessageError {
        message_id: MessageId<SP>,
        description: String,
    },
}
