use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
};
use core::{fmt::Debug, marker::PhantomData};

use signature::Keypair;

use super::{
    evidence::{ConflictingMessagesEvidence, Evidence, SenderErrorEvidence},
    message::{MessageId, MessageWithId, SignedValue, VerifiedValue},
    ruleset::{Action, ActionGroup, OnError, Ruleset},
    session_id::SessionId,
    storage::Storage,
    task::{
        FinalizeWithStallTask, FinalizeWithSuccessTask, PreprocessingResult, PreprocessingResultEnum,
        PreprocessingTask, Task, TaskResult, TaskResultEnum,
    },
};
use crate::{
    error::LocalError,
    protocol::{
        ArgNodes, Args, ArrayFunction, ExecutableProtocol, FullName, PrivateInputs, ScalarFunction, SessionParameters,
        Tag, Value,
    },
};

#[cfg(any(test, feature = "dev"))]
use crate::dev::Replacement;

#[derive(Debug)]
pub(crate) struct SessionData<SP: SessionParameters> {
    pub(crate) id: SessionId<SP>,
    pub(crate) participants: BTreeSet<SP::Verifier>,
    pub(crate) local_participants: BTreeSet<SP::Verifier>,
    pub(crate) expected_messages: BTreeMap<FullName, BTreeSet<SP::Verifier>>,
}

#[derive(Debug)]
pub struct Session<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    ruleset: Ruleset<SP>,
    storage: Storage<SP::Verifier>,
    signer: Option<Arc<SP::Signer>>,
    verifier: SP::Verifier,
    data: Arc<SessionData<SP>>,
    provable_errors: BTreeMap<SP::Verifier, Evidence<SP, P>>,
    attributable_errors: BTreeMap<SP::Verifier, String>,
    phantom: PhantomData<P>,
}

impl<SP, P> Session<SP, P>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    pub fn new(
        id: SessionId<SP>,
        signer: SP::Signer,
        private_data: &P::PrivateData,
        shared_data: &P::SharedData,
    ) -> Result<Self, LocalError> {
        let verifier = signer.verifying_key();

        let build_data = P::make_build_data(shared_data);
        let signature = P::signature();
        let arg_nodes = ArgNodes::new(&signature);
        let output_node = P::build(&signer.verifying_key(), &build_data, arg_nodes)?;

        let participants = P::all_participants(shared_data);
        let local_participants = BTreeSet::from([signer.verifying_key()]);
        let public_inputs = P::make_public_inputs(shared_data);
        let private_inputs = P::make_private_inputs(private_data);

        let ruleset = Ruleset::new(&output_node, &private_inputs.names())?;
        let expected_messages = ruleset.expected_messages().clone();
        let storage = Storage::new(public_inputs, private_inputs);
        let data = Arc::new(SessionData {
            id,
            participants,
            local_participants,
            expected_messages,
        });
        Ok(Self {
            ruleset,
            storage,
            signer: Some(Arc::new(signer)),
            verifier,
            data,
            provable_errors: BTreeMap::new(),
            attributable_errors: BTreeMap::new(),
            phantom: PhantomData,
        })
    }

    pub(crate) fn new_subtree(
        id: SessionId<SP>,
        subtree_root: &Tag,
        verifier: &SP::Verifier,
        shared_data: &P::SharedData,
    ) -> Result<Self, LocalError> {
        // TODO: extract common code with new()

        let build_data = P::make_build_data(shared_data);
        let signature = P::signature();
        let arg_nodes = ArgNodes::new(&signature);
        let output_node = P::build(verifier, &build_data, arg_nodes)?.get_subtree(subtree_root)?;

        let participants = P::all_participants(shared_data);
        let local_participants = BTreeSet::from([verifier.clone()]);

        let private_inputs = PrivateInputs::new();
        let public_inputs = P::make_public_inputs(shared_data);

        // TODO: we only need rules leading to `failed_at[guilty_party]`, not the whole `failed_at` array.
        let ruleset = Ruleset::new(&output_node, &BTreeSet::new())?;
        let expected_messages = ruleset.expected_messages().clone();
        let storage = Storage::new(public_inputs, private_inputs);
        let data = Arc::new(SessionData {
            id,
            participants,
            local_participants,
            expected_messages,
        });
        Ok(Self {
            ruleset,
            storage,
            signer: None,
            verifier: verifier.clone(),
            data,
            provable_errors: BTreeMap::new(),
            attributable_errors: BTreeMap::new(),
            phantom: PhantomData,
        })
    }

    #[cfg(any(test, feature = "dev"))]
    pub fn new_with_replacements(
        id: SessionId<SP>,
        signer: SP::Signer,
        private_data: &P::PrivateData,
        shared_data: &P::SharedData,
        replacement: Replacement<SP>,
    ) -> Result<Self, LocalError> {
        let verifier = signer.verifying_key();

        let build_data = P::make_build_data(shared_data);
        let signature = P::signature();
        let arg_nodes = ArgNodes::new(&signature);
        let output_node = P::build(&signer.verifying_key(), &build_data, arg_nodes)?;

        let output_node = replacement.apply(output_node)?;

        let participants = P::all_participants(shared_data);
        let local_participants = BTreeSet::from([signer.verifying_key()]);
        let public_inputs = P::make_public_inputs(shared_data);
        let private_inputs = P::make_private_inputs(private_data);

        let ruleset = Ruleset::new(&output_node, &private_inputs.names())?;
        let expected_messages = ruleset.expected_messages().clone();
        let storage = Storage::new(public_inputs, private_inputs);
        let data = Arc::new(SessionData {
            id,
            participants,
            local_participants,
            expected_messages,
        });
        Ok(Self {
            ruleset,
            storage,
            signer: Some(Arc::new(signer)),
            verifier,
            data,
            provable_errors: BTreeMap::new(),
            attributable_errors: BTreeMap::new(),
            phantom: PhantomData,
        })
    }

    pub fn verifier(&self) -> &SP::Verifier {
        &self.verifier
    }

    fn register_provable_error(&mut self, evidence: Evidence<SP, P>) {
        self.ruleset.update_with_banned_party(evidence.guilty_party());
        self.provable_errors.insert(evidence.guilty_party().clone(), evidence);
    }

    fn register_attributable_error(&mut self, guilty_party: SP::Verifier, tag: Tag) {
        self.ruleset.update_with_banned_party(&guilty_party);
        self.attributable_errors
            .insert(guilty_party, format!("Error when calculating {tag}"));
    }

    pub fn make_report(self, outcome: SessionOutcome<SP, P>) -> SessionReport<SP, P> {
        SessionReport::<SP, P> {
            outcome,
            provable_errors: self.provable_errors,
            attributable_errors: self.attributable_errors,
        }
    }

    pub fn finalize_with_success(self, task: FinalizeWithSuccessTask) -> Result<SessionReport<SP, P>, LocalError> {
        let value = self.storage.get(task.output_tag())?;
        let result = value.downcast::<P::Output>()?;
        Ok(self.make_report(SessionOutcome::Success(result)))
    }

    pub fn finalize_with_stalled(self, task: FinalizeWithStallTask) -> SessionReport<SP, P> {
        self.make_report(SessionOutcome::Unfinishable(format!(
            "Stalled at {}",
            task.stalled_tag()
        )))
    }

    pub fn terminate(self) -> SessionReport<SP, P> {
        self.make_report(SessionOutcome::ManuallyTerminated)
    }

    pub fn make_task(&mut self) -> Result<Option<Task<SP>>, LocalError> {
        while let Some(action_group) = self.ruleset.pop_action()? {
            let action = match action_group {
                ActionGroup::Action(action) => action,
                ActionGroup::ReturnOutput(tag) => {
                    return Ok(Some(Task::finalize_with_success(tag)));
                }
                ActionGroup::Terminate(tag) => {
                    return Ok(Some(Task::finalize_with_stall(tag)));
                }
            };

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
                    let args = Args::new(store_in.full_name(), &self.data, self.verifier(), arg_values)?;
                    return Ok(Some(match function {
                        ScalarFunction::Infallible(function) => {
                            Task::compute_scalar_infallible(store_in, function, args)
                        }
                        ScalarFunction::InfallibleWithRng(function) => {
                            Task::compute_scalar_infallible_with_rng(store_in, function, args)
                        }
                    }));
                }
                Action::ComputeArrayElement {
                    store_in,
                    function,
                    index,
                    args,
                    on_error,
                } => {
                    let arg_values = self.storage.get_scalar_or_array_args(&index, args)?;
                    let args = Args::new(store_in.full_name(), &self.data, self.verifier(), arg_values)?;
                    return Ok(Some(match function {
                        ArrayFunction::Infallible(function) => {
                            Task::compute_array_elem_infallible(store_in, index, function, args)
                        }
                        ArrayFunction::InfallibleWithRng(function) => {
                            Task::compute_array_elem_infallible_with_rng(store_in, index, function, args)
                        }
                        ArrayFunction::InfallibleWithSigner(function) => {
                            let signer = self
                                .signer
                                .as_ref()
                                .ok_or_else(|| LocalError::new("This session does not contain a signer"))?;
                            Task::compute_array_elem_infallible_with_signer(store_in, signer, index, function, args)
                        }
                        ArrayFunction::SenderAttributable(function) => {
                            Task::compute_array_elem_sender_attributable(store_in, index, function, args, on_error)
                        }
                        ArrayFunction::ThirdPartyAttributable(function) => {
                            Task::compute_array_elem_third_party_attributable(store_in, index, function, args)
                        }
                    }));
                }
                Action::Collect { store_in, values } => {
                    self.storage.set(&store_in, self.storage.get_dict_as_value(&values)?)?;
                    self.ruleset.update_with_value_ready(&store_in);
                }
            }
        }

        Ok(None)
    }

    pub(crate) fn make_preprocessing_task(
        &self,
        message_id: &MessageId<SP>,
        signed_value: SignedValue<SP>,
    ) -> PreprocessingTask<SP> {
        PreprocessingTask::new(&self.data, message_id.clone(), signed_value)
    }

    pub fn preprocess_message(&self, message: MessageWithId<SP>) -> impl Iterator<Item = PreprocessingTask<SP>> {
        let message_id = message.id().clone();
        message
            .into_values()
            .map(move |signed_value| self.make_preprocessing_task(&message_id, signed_value))
    }

    pub fn add_preprocess_result(&mut self, result: PreprocessingResult<SP>) -> Result<(), PreprocessingError<SP>> {
        match result.into_enum() {
            PreprocessingResultEnum::Success { store_in, id, value } => {
                if let Ok(existing_value) = self.storage.get_elem(&store_in, &id) {
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
                        let evidence = Evidence::ConflictingMessages(ConflictingMessagesEvidence::new(
                            &self.data.id,
                            &id,
                            typed_existing_value,
                            typed_received_value,
                        ));
                        self.register_provable_error(evidence);
                        return Ok(());
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

                self.storage.set_elem(&store_in, &id, value)?;
                self.ruleset.update_with_array_element_ready(&store_in, &id);

                Ok(())
            }
            PreprocessingResultEnum::MessageError {
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
            TaskResultEnum::SenderError { store_in, id, on_error } => match on_error {
                OnError::Escalate => self.register_attributable_error(id, store_in),
                OnError::CollectEvidence(message_names) => {
                    let mut signed_values = BTreeMap::new();
                    for name in message_names {
                        let value = self.storage.get_elem(&Tag::signed_remote_with_full_name(&name), &id)?;
                        let signed_value = value.downcast_ref::<VerifiedValue<SP>>()?.clone().unverify();
                        signed_values.insert(name.clone(), signed_value);
                    }
                    let evidence = Evidence::SenderError(SenderErrorEvidence::new(
                        &self.data.id,
                        &id,
                        &self.verifier,
                        &store_in,
                        signed_values,
                    ));
                    self.register_provable_error(evidence);
                }
            },
            TaskResultEnum::ThirdPartyError { .. } => todo!(),
        }
        Ok(())
    }
}

#[derive_where::derive_where(Debug)]
pub enum PreprocessingError<SP: SessionParameters> {
    Local(LocalError),
    InvalidMessage(InvalidMessageError<SP>),
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
pub struct DuplicateMessagesError<SP: SessionParameters> {
    pub first: MessageId<SP>,
    pub second: MessageId<SP>,
}

#[derive(Debug, Clone)]
pub struct SessionReport<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    pub outcome: SessionOutcome<SP, P>,
    pub provable_errors: BTreeMap<SP::Verifier, Evidence<SP, P>>,
    pub attributable_errors: BTreeMap<SP::Verifier, String>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> SessionReport<SP, P> {
    pub fn success(self) -> Option<P::Output> {
        if let SessionOutcome::Success(output) = self.outcome {
            Some(output)
        } else {
            None
        }
    }

    pub fn success_ref(&self) -> Option<&P::Output> {
        if let SessionOutcome::Success(output) = &self.outcome {
            Some(output)
        } else {
            None
        }
    }

    pub fn is_unfinishable(&self) -> bool {
        matches!(self.outcome, SessionOutcome::Unfinishable(..))
    }
}

#[derive(Debug, Clone)]
pub enum SessionOutcome<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    Success(P::Output),
    ManuallyTerminated,
    Unfinishable(String),
}
