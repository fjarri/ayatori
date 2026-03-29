use alloc::{format, string::String, sync::Arc, vec};
use core::fmt::Debug;

use signature::rand_core::CryptoRngCore;

use super::session::SessionData;
use crate::{
    entities::{
        Args, AssociatedData, CollectedTag, ComputedMappingTag, ComputedScalarTag, DeserializeArgs,
        DeserializeFunction, InfallibleMappingFunction, InfallibleMappingFunctionWithRng, InfallibleScalarFunction,
        InfallibleScalarFunctionWithRng, LocalSignedTag, MappingTag, Message, MessageId, ReceivedTag, RemoteSignedTag,
        ScalarTag, SenderAttributableMappingFunction, SenderError, SenderErrorEnum, SentTag, SerializeAndSignFunction,
        SerializeArgs, SignedValue, ThirdPartyAttributableMappingFunction, ThirdPartyError, ThirdPartyErrorEnum, Value,
        VerificationError,
    },
    errors::LocalError,
    flat_representation::OnError,
    traits::SessionParameters,
};

#[derive_where::derive_where(Debug)]
enum ComputeFunction<SP: SessionParameters> {
    ScalarInfallible {
        store_in: ComputedScalarTag,
        function: InfallibleScalarFunction<SP>,
        args: Args<SP>,
    },
    MappingInfallible {
        store_in: ComputedMappingTag,
        function: InfallibleMappingFunction<SP>,
        id: SP::Verifier,
        args: Args<SP>,
    },
    MappingSenderAttributable {
        store_in: ComputedMappingTag,
        function: SenderAttributableMappingFunction<SP>,
        id: SP::Verifier,
        args: Args<SP>,
        on_error: OnError,
    },
    MappingThirdPartyAttributable {
        store_in: ComputedMappingTag,
        function: ThirdPartyAttributableMappingFunction<SP>,
        id: SP::Verifier,
        args: Args<SP>,
    },
    Deserialize {
        store_in: ReceivedTag,
        function: DeserializeFunction<SP>,
        id: SP::Verifier,
        args: DeserializeArgs<SP>,
        on_error: OnError,
    },
    PreprocessMessage {
        task: PreprocessingTask<SP>,
    },
}

#[derive_where::derive_where(Debug)]
pub struct ComputeTask<SP: SessionParameters> {
    function: ComputeFunction<SP>,
}

impl<SP: SessionParameters> ComputeTask<SP> {
    pub fn compute(self) -> Result<TaskResult<SP>, LocalError> {
        match self.function {
            ComputeFunction::ScalarInfallible {
                store_in,
                function,
                args,
            } => {
                let store_in = ScalarTag::Computed(store_in);
                let result = function.call(&args)?;
                Ok(TaskResult(TaskResultEnum::Compute { store_in, result }))
            }
            ComputeFunction::MappingInfallible {
                store_in,
                function,
                id,
                args,
            } => {
                let store_in = MappingTag::Computed(store_in);
                let result = function.call(&id, &args)?;
                Ok(TaskResult(TaskResultEnum::ComputeMapping { store_in, id, result }))
            }
            ComputeFunction::MappingSenderAttributable {
                store_in,
                function,
                id,
                args,
                on_error,
            } => {
                let store_in = MappingTag::Computed(store_in);
                let result = match function.call(&id, &args) {
                    Ok(result) => result,
                    Err(SenderError(SenderErrorEnum::Local(error))) => return Err(error),
                    Err(SenderError(SenderErrorEnum::Error)) => {
                        return Ok(TaskResult(TaskResultEnum::SenderError { store_in, id, on_error }));
                    }
                };
                Ok(TaskResult(TaskResultEnum::ComputeMapping { store_in, id, result }))
            }
            ComputeFunction::MappingThirdPartyAttributable {
                store_in,
                function,
                id,
                args,
            } => {
                let store_in = MappingTag::Computed(store_in);
                let result = match function.call(&id, &args) {
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
                Ok(TaskResult(TaskResultEnum::ComputeMapping { store_in, id, result }))
            }
            ComputeFunction::Deserialize {
                store_in,
                function,
                id,
                args,
                on_error,
            } => {
                let store_in = MappingTag::Received(store_in);
                let result = match function.call(&args) {
                    Ok(result) => result,
                    Err(SenderError(SenderErrorEnum::Local(error))) => return Err(error),
                    Err(SenderError(SenderErrorEnum::Error)) => {
                        return Ok(TaskResult(TaskResultEnum::SenderError { store_in, id, on_error }));
                    }
                };
                Ok(TaskResult(TaskResultEnum::ComputeMapping { store_in, id, result }))
            }
            ComputeFunction::PreprocessMessage { task } => task.execute(),
        }
    }
}

#[derive_where::derive_where(Debug)]
enum ComputeWithRngFunction<SP: SessionParameters> {
    ScalarInfallible {
        store_in: ComputedScalarTag,
        function: InfallibleScalarFunctionWithRng<SP>,
        args: Args<SP>,
    },
    MappingInfallible {
        store_in: ComputedMappingTag,
        function: InfallibleMappingFunctionWithRng<SP>,
        id: SP::Verifier,
        args: Args<SP>,
    },
    SerializeAndSign {
        store_in: LocalSignedTag,
        function: SerializeAndSignFunction<SP>,
        id: SP::Verifier,
        args: SerializeArgs<SP>,
    },
}

#[derive_where::derive_where(Debug)]
pub struct ComputeWithRngTask<SP: SessionParameters> {
    function: ComputeWithRngFunction<SP>,
}

impl<SP: SessionParameters> ComputeWithRngTask<SP> {
    pub fn compute(self, rng: &mut impl CryptoRngCore) -> Result<TaskResult<SP>, LocalError> {
        match self.function {
            ComputeWithRngFunction::ScalarInfallible {
                store_in,
                function,
                args,
            } => {
                let store_in = ScalarTag::Computed(store_in);
                let result = function.call(rng, &args)?;
                Ok(TaskResult(TaskResultEnum::Compute { store_in, result }))
            }
            ComputeWithRngFunction::MappingInfallible {
                store_in,
                function,
                id,
                args,
            } => {
                let store_in = MappingTag::Computed(store_in);
                let result = function.call(rng, &id, &args)?;
                Ok(TaskResult(TaskResultEnum::ComputeMapping { store_in, id, result }))
            }
            ComputeWithRngFunction::SerializeAndSign {
                store_in,
                function,
                id,
                args,
            } => {
                let store_in = MappingTag::LocalSigned(store_in);
                let result = function.call(rng, &id, &args)?;
                Ok(TaskResult(TaskResultEnum::ComputeMapping { store_in, id, result }))
            }
        }
    }
}

#[derive_where::derive_where(Debug)]
pub struct SendTask<SP: SessionParameters> {
    store_in: SentTag,
    destination: SP::Verifier,
    signed_value: Value,
}

impl<SP: SessionParameters> SendTask<SP> {
    pub fn compute(self) -> Result<(Message<SP>, TaskResult<SP>), LocalError> {
        let signed_value = self.signed_value.downcast::<SignedValue<SP>>()?;
        let signed_values = vec![signed_value];
        let message = Message::new(self.destination.clone(), signed_values);
        let result = TaskResult(TaskResultEnum::Send {
            store_in: MappingTag::Sent(self.store_in.clone()),
            destination: self.destination.clone(),
        });
        Ok((message, result))
    }
}

#[derive(Debug, Clone)]
pub struct FinalizeWithSuccessTask(ComputedScalarTag);

impl FinalizeWithSuccessTask {
    pub(crate) fn output_tag(&self) -> &ComputedScalarTag {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct FinalizeWithStallTask(CollectedTag);

impl FinalizeWithStallTask {
    pub(crate) fn stalled_tag(&self) -> &CollectedTag {
        &self.0
    }
}

#[derive_where::derive_where(Debug)]
pub enum Task<SP: SessionParameters> {
    Send(SendTask<SP>),
    Compute(ComputeTask<SP>),
    ComputeWithRng(ComputeWithRngTask<SP>),
    FinalizeWithSuccess(FinalizeWithSuccessTask),
    FinalizeWithStall(FinalizeWithStallTask),
}

impl<SP: SessionParameters> Task<SP> {
    pub(crate) fn preprocess_message(task: PreprocessingTask<SP>) -> Self {
        Self::Compute(ComputeTask {
            function: ComputeFunction::PreprocessMessage { task },
        })
    }

    pub(crate) fn finalize_with_success(tag: ComputedScalarTag) -> Self {
        Self::FinalizeWithSuccess(FinalizeWithSuccessTask(tag))
    }

    pub(crate) fn finalize_with_stall(tag: CollectedTag) -> Self {
        Self::FinalizeWithStall(FinalizeWithStallTask(tag))
    }

    pub(crate) fn send(store_in: SentTag, destination: SP::Verifier, signed_value: Value) -> Self {
        Self::Send(SendTask {
            store_in,
            destination,
            signed_value,
        })
    }

    pub(crate) fn compute_scalar_infallible(
        store_in: ComputedScalarTag,
        function: InfallibleScalarFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask {
            function: ComputeFunction::ScalarInfallible {
                store_in,
                function,
                args,
            },
        })
    }

    pub(crate) fn compute_scalar_infallible_with_rng(
        store_in: ComputedScalarTag,
        function: InfallibleScalarFunctionWithRng<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask {
            function: ComputeWithRngFunction::ScalarInfallible {
                store_in,
                function,
                args,
            },
        })
    }

    pub(crate) fn compute_mapping_elem_infallible(
        store_in: ComputedMappingTag,
        id: SP::Verifier,
        function: InfallibleMappingFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask {
            function: ComputeFunction::MappingInfallible {
                store_in,
                id,
                function,
                args,
            },
        })
    }

    pub(crate) fn compute_mapping_elem_infallible_with_rng(
        store_in: ComputedMappingTag,
        id: SP::Verifier,
        function: InfallibleMappingFunctionWithRng<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask {
            function: ComputeWithRngFunction::MappingInfallible {
                store_in,
                id,
                function,
                args,
            },
        })
    }

    pub(crate) fn compute_serialize_and_sign_elem(
        store_in: LocalSignedTag,
        id: SP::Verifier,
        function: SerializeAndSignFunction<SP>,
        args: SerializeArgs<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask {
            function: ComputeWithRngFunction::SerializeAndSign {
                store_in,
                id,
                function,
                args,
            },
        })
    }

    pub(crate) fn compute_deserialize_elem(
        store_in: ReceivedTag,
        id: SP::Verifier,
        function: DeserializeFunction<SP>,
        args: DeserializeArgs<SP>,
        on_error: OnError,
    ) -> Self {
        Self::Compute(ComputeTask {
            function: ComputeFunction::Deserialize {
                store_in,
                id,
                function,
                args,
                on_error,
            },
        })
    }

    pub(crate) fn compute_mapping_elem_sender_attributable(
        store_in: ComputedMappingTag,
        id: SP::Verifier,
        function: SenderAttributableMappingFunction<SP>,
        args: Args<SP>,
        on_error: OnError,
    ) -> Self {
        Self::Compute(ComputeTask {
            function: ComputeFunction::MappingSenderAttributable {
                store_in,
                id,
                function,
                args,
                on_error,
            },
        })
    }

    pub(crate) fn compute_mapping_elem_third_party_attributable(
        store_in: ComputedMappingTag,
        id: SP::Verifier,
        function: ThirdPartyAttributableMappingFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask {
            function: ComputeFunction::MappingThirdPartyAttributable {
                store_in,
                id,
                function,
                args,
            },
        })
    }
}

#[derive(Debug)]
pub struct TaskResult<SP: SessionParameters>(TaskResultEnum<SP>);

impl<SP: SessionParameters> TaskResult<SP> {
    pub(crate) fn as_enum(&self) -> &TaskResultEnum<SP> {
        &self.0
    }

    pub(crate) fn into_enum(self) -> TaskResultEnum<SP> {
        self.0
    }
}

#[derive(Debug)]
pub(crate) enum TaskResultEnum<SP: SessionParameters> {
    Send {
        store_in: MappingTag,
        destination: SP::Verifier,
    },
    Compute {
        store_in: ScalarTag,
        result: Value,
    },
    ComputeMapping {
        store_in: MappingTag,
        id: SP::Verifier,
        result: Value,
    },
    SenderError {
        store_in: MappingTag,
        id: SP::Verifier,
        on_error: OnError,
    },
    ThirdPartyError {
        store_in: MappingTag,
        id: SP::Verifier,
        associated_data: AssociatedData<SP>,
    },
    PreprocessingSuccess {
        store_in: MappingTag,
        id: SP::Verifier,
        value: Value,
    },
    MessageError {
        message_id: MessageId<SP>,
        description: String,
    },
}

#[derive_where::derive_where(Debug)]
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

    pub fn execute(self) -> Result<TaskResult<SP>, LocalError> {
        // Before storing the value in the database, we check for the failures that are unattributable at this level.
        // In case of a failure all we can do is report the message ID and let the user deal with it
        // if their transport protocol allows it.

        // TODO (#60): reject messages from already banned nodes

        let source = self.signed_value.source().clone();

        // Check that the value is from one of the session participants.
        // If it is not, even if we detect something provably wrong with it,
        // the proof will be useless.
        if !self.session_data.participants.contains(self.signed_value.source()) {
            return Ok(TaskResult(TaskResultEnum::MessageError {
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
            return Ok(TaskResult(TaskResultEnum::MessageError {
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
            return Ok(TaskResult(TaskResultEnum::MessageError {
                message_id: self.message_id,
                description: "Invalid session ID".into(),
            }));
        }

        // Verify the value signature.
        let verified_value = match self.signed_value.verify(&self.message_id) {
            Ok(value) => value,
            Err(VerificationError::Local(error)) => return Err(error),
            Err(VerificationError::SignatureMismatch) => {
                return Ok(TaskResult(TaskResultEnum::MessageError {
                    message_id: self.message_id.clone(),
                    description: format!("Verification error for a message from {source:?}"),
                }));
            }
        };

        let store_in = RemoteSignedTag::new_with_full_name(verified_value.metadata().full_name());
        let value = Value::new(verified_value);

        Ok(TaskResult(TaskResultEnum::PreprocessingSuccess {
            store_in: MappingTag::RemoteSigned(store_in),
            id: source,
            value,
        }))
    }
}
