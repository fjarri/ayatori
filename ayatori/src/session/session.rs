use alloc::{boxed::Box, collections::BTreeSet, format, string::String, sync::Arc};
use core::{fmt::Debug, marker::PhantomData};

use signature::Keypair;

use super::{
    message::{MessageId, MessageWithId, SignedValue, VerifiedValue},
    ruleset::{Action, Ruleset},
    session_id::SessionId,
    storage::Storage,
    task::{PreprocessResult, PreprocessResultEnum, PreprocessTask, Task, TaskResult, TaskResultEnum},
};
use crate::{
    error::LocalError,
    protocol::{Args, ArrayFunction, ExecutableProtocol, ScalarFunction, SessionParameters, Value},
};

// TODO: do we need to be generic over P here?
#[derive(Debug)]
pub struct Session<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    id: SessionId<SP>,
    signer: Arc<SP::Signer>,
    ruleset: Ruleset<SP>,
    storage: Storage<SP::Verifier>,
    participants: Arc<BTreeSet<SP::Verifier>>,
    local_participants: Arc<BTreeSet<SP::Verifier>>,
    phantom: PhantomData<P>,
}

impl<SP, P> Session<SP, P>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    pub fn new(id: SessionId<SP>, signer: SP::Signer, shared_data: &P::SharedData) -> Result<Self, LocalError> {
        let participants = Arc::new(P::all_participants(shared_data));
        let local_participants = Arc::new(BTreeSet::from([signer.verifying_key()]));
        let inputs = P::make_inputs(shared_data);
        let build_data = P::make_build_data(shared_data);
        let output_node = P::build(&signer.verifying_key(), &build_data, inputs)?;
        let ruleset = Ruleset::new(output_node)?;
        let storage = Storage::new();
        let signer = Arc::new(signer);
        Ok(Self {
            id,
            signer,
            ruleset,
            storage,
            participants,
            local_participants,
            phantom: PhantomData,
        })
    }

    pub fn verifier(&self) -> SP::Verifier {
        self.signer.verifying_key()
    }

    pub fn make_task(&mut self) -> Result<Option<Task<SP>>, LocalError> {
        if self.storage.contains(self.ruleset.output_tag()) {
            return Ok(Some(Task::finalize(self.storage.get(self.ruleset.output_tag())?)));
        }

        if self.ruleset.is_empty() {
            return Err(LocalError::new(
                "No rules to apply, and the output value has not been set",
            ));
        }

        loop {
            let Some(action) = self.ruleset.pop_action() else { break };

            match action {
                Action::Send {
                    store_in,
                    to_send,
                    destination,
                    index,
                } => {
                    let signed_value = if let Some(index) = index {
                        self.storage.get_elem(&to_send, &index)
                    } else {
                        self.storage.get(&to_send)
                    }?;

                    return Ok(Some(Task::send(store_in, destination, signed_value)));
                }
                Action::ComputeScalar {
                    store_in,
                    function,
                    args,
                } => {
                    let arg_values = self.storage.get_scalar_args(args)?;
                    let args = Args::new(&self.signer, &self.id, &self.verifier(), arg_values)?;
                    match function {
                        ScalarFunction::Public(function) => {
                            return Ok(Some(Task::compute_scalar(store_in, function, args)));
                        }
                        ScalarFunction::Private(function) => {
                            return Ok(Some(Task::compute_scalar_with_rng(store_in, function, args)));
                        }
                    }
                }
                Action::ComputeArrayElement {
                    store_in,
                    function,
                    index,
                    args,
                } => {
                    let arg_values = self.storage.get_scalar_or_array_args(&index, args)?;
                    let args = Args::new(&self.signer, &self.id, &self.verifier(), arg_values)?;
                    match function {
                        ArrayFunction::Public(function) => {
                            return Ok(Some(Task::compute_array_elem(store_in, index, function, args)));
                        }
                        ArrayFunction::Private(function) => {
                            return Ok(Some(Task::compute_array_elem_with_rng(store_in, index, function, args)));
                        }
                    }
                }
                Action::Collect { store_in, values } => {
                    self.storage.set(&store_in, self.storage.get_dict_as_value(&values)?)?;
                    self.ruleset.update_with_value_ready(&store_in);
                }
            }
        }

        Ok(None)
    }

    pub fn preprocess_message(&mut self, message: MessageWithId<SP>) -> PreprocessTask<SP> {
        PreprocessTask::new(message, &self.participants, &self.local_participants)
    }

    pub fn add_preprocess_result(&mut self, result: PreprocessResult<SP>) -> Result<(), PreprocessingError<SP>> {
        match result.into_enum() {
            PreprocessResultEnum::Success { to_store } => {
                for (tag, id, value) in to_store.iter() {
                    if let Ok(existing_value) = self.storage.get_elem(tag, id) {
                        let typed_existing_value = existing_value.downcast_ref::<VerifiedValue<SP>>()?;
                        let typed_received_value = value.downcast_ref::<VerifiedValue<SP>>()?;

                        // Both values are signed, contain the same named value, but are different.
                        // This is a provable failure.
                        // Note that the payload or metadata of either value may still be invalid
                        // (it is possible that it has not been checked yet at this point),
                        // but it does not matter since we already got our evidence.
                        if typed_existing_value.metadata() != typed_received_value.metadata()
                            || typed_existing_value.serialized_value() != typed_received_value.serialized_value()
                        {
                            // TODO (#7): to be packed into an evidence.
                            return Err(PreprocessingError::ConflictingMessages(
                                ConflictingMessagesError {
                                    guilty_party: id.clone(),
                                    first: typed_existing_value.clone().unverify(),
                                    second: typed_received_value.clone().unverify(),
                                }
                                .into(),
                            ));
                        }

                        // The message is a duplicate, we cannot do anything at this point.
                        // If the payload/metadata are invalid, the later checks will produce verifiable evidence.
                        // For now we can only report both message IDs that delivered these values,
                        // and let the user deal with it, if possible.
                        return Err(PreprocessingError::DuplicateMessages(DuplicateMessagesError {
                            first: typed_existing_value.message_id().clone(),
                            second: typed_existing_value.message_id().clone(),
                        }));
                    }
                }
                for (tag, id, value) in to_store {
                    self.storage.set_elem(&tag, &id, value)?;
                    self.ruleset.update_with_array_element_ready(&tag, &id);
                }
                Ok(())
            }
            PreprocessResultEnum::MessageError {
                message_id,
                description,
            } => Err(PreprocessingError::InvalidMessage(InvalidMessageError {
                message_id,
                description,
            })),
        }
    }

    pub fn add_result(&mut self, result: TaskResult<SP::Verifier>) -> Result<(), LocalError> {
        match result.into_enum() {
            TaskResultEnum::Send { store_in, destination } => {
                self.storage.set_elem(&store_in, &destination, Value::new(()))?;
                self.ruleset.update_with_array_element_ready(&store_in, &destination);
            }
            TaskResultEnum::Compute { store_in, result } => {
                self.storage.set(&store_in, result)?;
                self.ruleset.update_with_value_ready(&store_in);
            }
            TaskResultEnum::ComputeArray { store_in, id, result } => {
                self.storage.set_elem(&store_in, &id, result)?;
                self.ruleset.update_with_array_element_ready(&store_in, &id);
            }
            TaskResultEnum::AttributableError { store_in, id } => {
                // TODO (#39): ban the node internally and carry on.
                // For now we are returning a `LocalError` right away.
                return Err(LocalError::new(format!(
                    "Attributable error when calculating {store_in}[{id:?}]"
                )));
            }
            TaskResultEnum::UnattributableError { store_in } => {
                return Err(LocalError::new(format!(
                    "Unattributable error when calculating {store_in}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum PreprocessingError<SP: SessionParameters> {
    Local(LocalError),
    InvalidMessage(InvalidMessageError<SP>),
    ConflictingMessages(Box<ConflictingMessagesError<SP>>),
    DuplicateMessages(DuplicateMessagesError<SP>),
}

#[derive_where::derive_where(Debug)]
pub struct InvalidMessageError<SP: SessionParameters> {
    pub message_id: MessageId<SP>,
    pub description: String,
}

impl<SP: SessionParameters> From<LocalError> for PreprocessingError<SP> {
    fn from(source: LocalError) -> Self {
        Self::Local(source)
    }
}

impl<SP: SessionParameters> From<InvalidMessageError<SP>> for PreprocessingError<SP> {
    fn from(source: InvalidMessageError<SP>) -> Self {
        Self::InvalidMessage(source)
    }
}

#[derive_where::derive_where(Debug)]
pub struct ConflictingMessagesError<SP: SessionParameters> {
    pub guilty_party: SP::Verifier,
    pub first: SignedValue<SP>,
    pub second: SignedValue<SP>,
}

#[derive_where::derive_where(Debug)]
pub struct DuplicateMessagesError<SP: SessionParameters> {
    pub first: MessageId<SP>,
    pub second: MessageId<SP>,
}
