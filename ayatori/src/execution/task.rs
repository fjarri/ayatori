use alloc::{format, string::String, sync::Arc, vec};

use signature::rand_core::CryptoRngCore;

use super::session::SessionData;
use crate::{
    entities::{
        Args, ComputedMappingTag, ComputedScalarTag, DeserializeArgs, DeserializeFunction, LocalSignedTag, MappingTag,
        Message, MessageId, ReceivedTag, RemoteSignedTag, RuntimeError, ScalarTag, SenderAttributableError,
        SenderAttributableErrorEnum, SenderAttributableErrorWithReveal, SenderAttributableErrorWithRevealEnum,
        SenderAttributableMappingFunction, SenderAttributableWithRevealMappingFunction, SenderError,
        SenderErrorWithReveal, SentTag, SerializeAndSignFunction, SerializeArgs, SignedValue,
        ThirdPartyAttributableError, ThirdPartyAttributableErrorEnum, ThirdPartyAttributableMappingFunction,
        ThirdPartyError, UnattributableError, UnattributableMappingFunction, UnattributableMappingFunctionWithRng,
        UnattributableOptionalScalarFunction, UnattributableScalarFunction, UnattributableScalarFunctionWithRng, Value,
        VerificationError,
    },
    error::{IntoTraced, ResultExt, TResult, Traced},
    flat_representation::OnError,
    traits::SessionParameters,
};

#[cfg(doc)]
use crate::protocol_user_api::Session;

#[derive_where::derive_where(Debug)]
enum ComputeTaskEnum<SP: SessionParameters> {
    ScalarUnattributable {
        store_in: ComputedScalarTag,
        function: UnattributableScalarFunction<SP>,
        args: Args<SP>,
    },
    ScalarUnattributableOptional {
        store_in: ComputedScalarTag,
        function: UnattributableOptionalScalarFunction<SP>,
        args: Args<SP>,
    },
    MappingElementUnattributable {
        store_in: ComputedMappingTag,
        function: UnattributableMappingFunction<SP>,
        source: SP::Verifier,
        args: Args<SP>,
    },
    MappingElementSenderAttributable {
        store_in: ComputedMappingTag,
        function: SenderAttributableMappingFunction<SP>,
        source: SP::Verifier,
        args: Args<SP>,
        on_error: OnError,
    },
    MappingElementSenderAttributableWithReveal {
        store_in: ComputedMappingTag,
        function: SenderAttributableWithRevealMappingFunction<SP>,
        source: SP::Verifier,
        args: Args<SP>,
        on_error: OnError,
    },
    MappingElementThirdPartyAttributable {
        store_in: ComputedMappingTag,
        function: ThirdPartyAttributableMappingFunction<SP>,
        source: SP::Verifier,
        args: Args<SP>,
    },
    DeserializeElement {
        store_in: ReceivedTag,
        function: DeserializeFunction<SP>,
        source: SP::Verifier,
        args: DeserializeArgs<SP>,
        on_error: OnError,
    },
    PreprocessMessage {
        task: PreprocessingTask<SP>,
    },
}

fn unattributable_error_to_result<SP: SessionParameters, E>(error: E) -> TaskResult<SP>
where
    UnattributableError: From<E>,
{
    TaskResult(TaskResultEnum::UnattributableError {
        error: Traced::from(UnattributableError::from(error)),
    })
}

#[derive_where::derive_where(Debug)]
pub struct ComputeTask<SP: SessionParameters>(ComputeTaskEnum<SP>);

impl<SP: SessionParameters> ComputeTask<SP> {
    pub fn compute(self) -> TaskResult<SP> {
        match self.0 {
            ComputeTaskEnum::ScalarUnattributable {
                store_in,
                function,
                args,
            } => {
                let store_in = ScalarTag::Computed(store_in);
                match function.call(&args) {
                    Ok(result) => TaskResult(TaskResultEnum::ComputedScalar { store_in, result }),
                    Err(error) => unattributable_error_to_result(error),
                }
            }
            ComputeTaskEnum::ScalarUnattributableOptional {
                store_in,
                function,
                args,
            } => {
                let store_in = ScalarTag::Computed(store_in);
                match function.call(&args) {
                    Ok(result) => TaskResult(result.map_or_else(
                        || TaskResultEnum::Success,
                        |value| TaskResultEnum::ComputedScalar {
                            store_in,
                            result: value,
                        },
                    )),
                    Err(error) => unattributable_error_to_result(error),
                }
            }
            ComputeTaskEnum::MappingElementUnattributable {
                store_in,
                function,
                source,
                args,
            } => {
                let store_in = MappingTag::Computed(store_in);
                match function.call(&source, &args) {
                    Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                        store_in,
                        source,
                        result,
                    }),
                    Err(error) => unattributable_error_to_result(error),
                }
            }
            ComputeTaskEnum::MappingElementSenderAttributable {
                store_in,
                function,
                source,
                args,
                on_error,
            } => {
                let store_in = MappingTag::Computed(store_in);
                match function.call(&source, &args) {
                    Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                        store_in,
                        source,
                        result,
                    }),
                    Err(SenderAttributableError(SenderAttributableErrorEnum::Unattributable(error))) => {
                        unattributable_error_to_result(error)
                    }
                    Err(SenderAttributableError(SenderAttributableErrorEnum::Attributable(error))) => {
                        TaskResult(TaskResultEnum::SenderError {
                            store_in,
                            guilty_party: source,
                            error,
                            on_error,
                        })
                    }
                }
            }
            ComputeTaskEnum::MappingElementSenderAttributableWithReveal {
                store_in,
                function,
                source,
                args,
                on_error,
            } => {
                let store_in = MappingTag::Computed(store_in);
                match function.call(&source, &args) {
                    Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                        store_in,
                        source,
                        result,
                    }),
                    Err(SenderAttributableErrorWithReveal(SenderAttributableErrorWithRevealEnum::Unattributable(
                        error,
                    ))) => unattributable_error_to_result(error),
                    Err(SenderAttributableErrorWithReveal(SenderAttributableErrorWithRevealEnum::Attributable(
                        error,
                    ))) => TaskResult(TaskResultEnum::SenderErrorWithReveal {
                        store_in,
                        guilty_party: source,
                        error,
                        on_error,
                    }),
                }
            }
            ComputeTaskEnum::MappingElementThirdPartyAttributable {
                store_in,
                function,
                source,
                args,
            } => {
                let store_in = MappingTag::Computed(store_in);
                match function.call(&source, &args) {
                    Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                        store_in,
                        source,
                        result,
                    }),
                    Err(ThirdPartyAttributableError(ThirdPartyAttributableErrorEnum::Unattributable(error))) => {
                        unattributable_error_to_result(error)
                    }
                    Err(ThirdPartyAttributableError(ThirdPartyAttributableErrorEnum::Attributable {
                        guilty_party,
                        error,
                    })) => TaskResult(TaskResultEnum::ThirdPartyError {
                        store_in,
                        guilty_party,
                        error,
                    }),
                }
            }
            ComputeTaskEnum::DeserializeElement {
                store_in,
                function,
                source,
                args,
                on_error,
            } => {
                let store_in = MappingTag::Received(store_in);
                match function.call(&args) {
                    Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                        store_in,
                        source,
                        result,
                    }),
                    Err(SenderAttributableError(SenderAttributableErrorEnum::Unattributable(error))) => {
                        unattributable_error_to_result(error)
                    }
                    Err(SenderAttributableError(SenderAttributableErrorEnum::Attributable(error))) => {
                        TaskResult(TaskResultEnum::SenderError {
                            store_in,
                            guilty_party: source,
                            error,
                            on_error,
                        })
                    }
                }
            }
            ComputeTaskEnum::PreprocessMessage { task } => match task.execute() {
                Ok(result) => result,
                Err(error) => TaskResult(TaskResultEnum::UnattributableError { error: error.trace() }),
            },
        }
    }
}

#[derive_where::derive_where(Debug)]
enum ComputeWithRngTaskEnum<SP: SessionParameters> {
    ScalarUnattributable {
        store_in: ComputedScalarTag,
        function: UnattributableScalarFunctionWithRng<SP>,
        args: Args<SP>,
    },
    MappingElementUnattributable {
        store_in: ComputedMappingTag,
        function: UnattributableMappingFunctionWithRng<SP>,
        source: SP::Verifier,
        args: Args<SP>,
    },
    SerializeAndSignElement {
        store_in: LocalSignedTag,
        function: SerializeAndSignFunction<SP>,
        source: SP::Verifier,
        args: SerializeArgs<SP>,
    },
}

#[derive_where::derive_where(Debug)]
pub struct ComputeWithRngTask<SP: SessionParameters>(ComputeWithRngTaskEnum<SP>);

impl<SP: SessionParameters> ComputeWithRngTask<SP> {
    pub fn compute(self, rng: &mut impl CryptoRngCore) -> TaskResult<SP> {
        match self.0 {
            ComputeWithRngTaskEnum::ScalarUnattributable {
                store_in,
                function,
                args,
            } => {
                let store_in = ScalarTag::Computed(store_in);
                match function.call(rng, &args) {
                    Ok(result) => TaskResult(TaskResultEnum::ComputedScalar { store_in, result }),
                    Err(error) => unattributable_error_to_result(error),
                }
            }
            ComputeWithRngTaskEnum::MappingElementUnattributable {
                store_in,
                function,
                source,
                args,
            } => {
                let store_in = MappingTag::Computed(store_in);
                match function.call(rng, &source, &args) {
                    Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                        store_in,
                        source,
                        result,
                    }),
                    Err(error) => unattributable_error_to_result(error),
                }
            }
            ComputeWithRngTaskEnum::SerializeAndSignElement {
                store_in,
                function,
                source,
                args,
            } => {
                let store_in = MappingTag::LocalSigned(store_in);
                match function.call(rng, &source, &args) {
                    Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                        store_in,
                        source,
                        result,
                    }),
                    Err(error) => unattributable_error_to_result(error),
                }
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
    pub fn compute(self) -> (Option<Message<SP>>, TaskResult<SP>) {
        let signed_value = match self.signed_value.downcast::<SignedValue<SP>>() {
            Ok(value) => value,
            Err(error) => return (None, unattributable_error_to_result(error)),
        };
        let signed_values = vec![signed_value];
        let message = Message::new(self.destination.clone(), signed_values);
        let result = TaskResult(TaskResultEnum::Sent {
            store_in: MappingTag::Sent(self.store_in.clone()),
            destination: self.destination,
        });
        (Some(message), result)
    }
}

/// A session task to be executed.
#[derive_where::derive_where(Debug)]
pub enum Task<SP: SessionParameters> {
    /// Send an outgoing message.
    Send(SendTask<SP>),
    /// Perform a dererministic computation.
    Compute(ComputeTask<SP>),
    /// Perform a computation that needs access to an RNG.
    ComputeWithRng(ComputeWithRngTask<SP>),
}

impl<SP: SessionParameters> Task<SP> {
    pub(crate) fn preprocess_message(task: PreprocessingTask<SP>) -> Self {
        Self::Compute(ComputeTask(ComputeTaskEnum::PreprocessMessage { task }))
    }

    pub(crate) fn direct_message(store_in: SentTag, destination: SP::Verifier, signed_value: Value) -> Self {
        Self::Send(SendTask {
            store_in,
            destination,
            signed_value,
        })
    }

    pub(crate) fn compute_scalar_unattributable(
        store_in: ComputedScalarTag,
        function: UnattributableScalarFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask(ComputeTaskEnum::ScalarUnattributable {
            store_in,
            function,
            args,
        }))
    }

    pub(crate) fn compute_scalar_unattributable_optional(
        store_in: ComputedScalarTag,
        function: UnattributableOptionalScalarFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask(ComputeTaskEnum::ScalarUnattributableOptional {
            store_in,
            function,
            args,
        }))
    }

    pub(crate) fn compute_scalar_unattributable_with_rng(
        store_in: ComputedScalarTag,
        function: UnattributableScalarFunctionWithRng<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask(ComputeWithRngTaskEnum::ScalarUnattributable {
            store_in,
            function,
            args,
        }))
    }

    pub(crate) fn compute_mapping_elem_unattributable(
        store_in: ComputedMappingTag,
        source: SP::Verifier,
        function: UnattributableMappingFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask(ComputeTaskEnum::MappingElementUnattributable {
            store_in,
            source,
            function,
            args,
        }))
    }

    pub(crate) fn compute_mapping_elem_unattributable_with_rng(
        store_in: ComputedMappingTag,
        source: SP::Verifier,
        function: UnattributableMappingFunctionWithRng<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask(
            ComputeWithRngTaskEnum::MappingElementUnattributable {
                store_in,
                source,
                function,
                args,
            },
        ))
    }

    pub(crate) fn compute_serialize_and_sign_elem(
        store_in: LocalSignedTag,
        source: SP::Verifier,
        function: SerializeAndSignFunction<SP>,
        args: SerializeArgs<SP>,
    ) -> Self {
        Self::ComputeWithRng(ComputeWithRngTask(ComputeWithRngTaskEnum::SerializeAndSignElement {
            store_in,
            source,
            function,
            args,
        }))
    }

    pub(crate) fn compute_deserialize_elem(
        store_in: ReceivedTag,
        source: SP::Verifier,
        function: DeserializeFunction<SP>,
        args: DeserializeArgs<SP>,
        on_error: OnError,
    ) -> Self {
        Self::Compute(ComputeTask(ComputeTaskEnum::DeserializeElement {
            store_in,
            source,
            function,
            args,
            on_error,
        }))
    }

    pub(crate) fn compute_mapping_elem_sender_attributable(
        store_in: ComputedMappingTag,
        source: SP::Verifier,
        function: SenderAttributableMappingFunction<SP>,
        args: Args<SP>,
        on_error: OnError,
    ) -> Self {
        Self::Compute(ComputeTask(ComputeTaskEnum::MappingElementSenderAttributable {
            store_in,
            source,
            function,
            args,
            on_error,
        }))
    }

    pub(crate) fn compute_mapping_elem_sender_attributable_with_reveal(
        store_in: ComputedMappingTag,
        source: SP::Verifier,
        function: SenderAttributableWithRevealMappingFunction<SP>,
        args: Args<SP>,
        on_error: OnError,
    ) -> Self {
        Self::Compute(ComputeTask(
            ComputeTaskEnum::MappingElementSenderAttributableWithReveal {
                store_in,
                source,
                function,
                args,
                on_error,
            },
        ))
    }

    pub(crate) fn compute_mapping_elem_third_party_attributable(
        store_in: ComputedMappingTag,
        source: SP::Verifier,
        function: ThirdPartyAttributableMappingFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self::Compute(ComputeTask(ComputeTaskEnum::MappingElementThirdPartyAttributable {
            store_in,
            source,
            function,
            args,
        }))
    }
}

#[derive_where::derive_where(Debug)]
pub struct TaskResult<SP: SessionParameters>(TaskResultEnum<SP>);

impl<SP: SessionParameters> TaskResult<SP> {
    pub(crate) fn into_enum(self) -> TaskResultEnum<SP> {
        self.0
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) enum TaskResultEnum<SP: SessionParameters> {
    Success,
    Sent {
        store_in: MappingTag,
        destination: SP::Verifier,
    },
    ComputedScalar {
        store_in: ScalarTag,
        result: Value,
    },
    ComputedMappingElement {
        store_in: MappingTag,
        source: SP::Verifier,
        result: Value,
    },
    UnattributableError {
        error: Traced<UnattributableError>,
    },
    SenderError {
        store_in: MappingTag,
        guilty_party: SP::Verifier,
        error: SenderError,
        on_error: OnError,
    },
    SenderErrorWithReveal {
        store_in: MappingTag,
        guilty_party: SP::Verifier,
        error: SenderErrorWithReveal<SP>,
        on_error: OnError,
    },
    ThirdPartyError {
        store_in: MappingTag,
        guilty_party: SP::Verifier,
        error: ThirdPartyError<SP>,
    },
    Preprocessed {
        store_in: MappingTag,
        source: SP::Verifier,
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

    pub fn execute(self) -> TResult<TaskResult<SP>, RuntimeError> {
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
            Err(VerificationError::Runtime(error)) => return Err(error).into_traced().trace(),
            Err(VerificationError::SignatureMismatch) => {
                return Ok(TaskResult(TaskResultEnum::MessageError {
                    message_id: self.message_id.clone(),
                    description: format!("Verification error for a message from {source:?}"),
                }));
            }
        };

        let store_in = RemoteSignedTag::new_with_full_name(verified_value.metadata().full_name());
        let value = Value::new(verified_value);

        Ok(TaskResult(TaskResultEnum::Preprocessed {
            store_in: MappingTag::RemoteSigned(store_in),
            source,
            value,
        }))
    }
}
