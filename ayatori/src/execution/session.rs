use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use itertools::Itertools;
use signature::Keypair;

use super::{
    evidence::{ConflictingMessagesEvidence, Evidence, EvidenceEnum, SenderErrorEvidence, ThirdPartyErrorEvidence},
    message::MessageWithId,
    session_id::SessionId,
    storage::Storage,
    task::{
        FinalizeWithStallTask, FinalizeWithSuccessTask, PreprocessingResult, PreprocessingResultEnum,
        PreprocessingTask, Task, TaskResult, TaskResultEnum,
    },
};
#[cfg(any(test, feature = "dev"))]
use crate::dev::Replacement;
use crate::{
    entities::{
        AnyTag, Args, DeserializeArgs, FullName, MappingFunction, MappingTag, MessageId, ScalarFunction, ScalarTag,
        SerializeArgs, SignedValue, Value, VerifiedValue,
    },
    errors::LocalError,
    flat_representation::{Action, OnError, Ruleset},
    graph_representation::{ArgNodes, Node, PrivateInputs, PublicInputs},
    traits::{ExecutableProtocol, SessionParameters},
};

#[derive(Debug)]
pub(crate) struct SessionData<SP: SessionParameters> {
    pub(crate) id: SessionId<SP>,
    pub(crate) participants: BTreeSet<SP::Verifier>,
    pub(crate) local_participants: BTreeSet<SP::Verifier>,
    pub(crate) expected_messages: BTreeMap<FullName, BTreeSet<SP::Verifier>>,
}

impl<SP: SessionParameters> SessionData<SP> {
    pub fn expected_senders(&self, message_name: &FullName) -> Option<BTreeSet<SP::Verifier>> {
        self.expected_messages.get(message_name).cloned()
    }
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

fn make_tree<SP, P>(verifier: &SP::Verifier, shared_data: &P::SharedData) -> Result<Node<SP>, LocalError>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    let build_data = P::make_build_data(shared_data);
    let signature = P::signature();
    let arg_nodes = ArgNodes::new(&signature);
    P::build(verifier, &build_data, arg_nodes)
}

impl<SP, P> Session<SP, P>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    fn new_inner(
        id: SessionId<SP>,
        signer: Option<SP::Signer>,
        verifier: &SP::Verifier,
        output_node: Node<SP>,
        private_inputs: PrivateInputs,
        shared_data: &P::SharedData,
    ) -> Result<Self, LocalError> {
        let participants = P::all_participants(shared_data);
        let local_participants = BTreeSet::from([verifier.clone()]);
        let public_inputs = P::make_public_inputs(shared_data);

        let ruleset = Ruleset::new(&output_node, &private_inputs.names())?;
        let storage = Storage::new();

        let expected_messages = ruleset.expected_messages().clone();
        let data = Arc::new(SessionData {
            id,
            participants,
            local_participants,
            expected_messages,
        });
        let mut session = Self {
            ruleset,
            storage,
            signer: signer.map(Arc::new),
            verifier: verifier.clone(),
            data,
            provable_errors: BTreeMap::new(),
            attributable_errors: BTreeMap::new(),
            phantom: PhantomData,
        };

        session.fill_inputs(public_inputs, private_inputs)?;

        Ok(session)
    }

    fn fill_inputs(&mut self, public_inputs: PublicInputs, private_inputs: PrivateInputs) -> Result<(), LocalError> {
        let arguments = self.ruleset.arguments().clone();

        let public_values = public_inputs.into_inner();
        let private_values = private_inputs.into_inner();

        let public_names = public_values.keys().collect::<BTreeSet<_>>();
        let private_names = private_values.keys().collect::<BTreeSet<_>>();

        if !public_names.is_disjoint(&private_names) {
            let mut intersection = public_names.intersection(&private_names);
            return Err(LocalError::new(format!(
                "Intersecting names in public and private arguments: {}",
                intersection.join(", ")
            )));
        }

        let all_names = public_names.union(&private_names).cloned().collect::<BTreeSet<_>>();
        if all_names != arguments.keys().collect() {
            return Err(LocalError::new(
                "Public and private argument names differ from the protocol signature",
            ));
        }

        for (name, value) in public_values {
            let store_in = arguments.get(&name).ok_or_else(|| {
                LocalError::new(format!("Public argument {name} not found in the protocol signature"))
            })?;
            self.add_scalar(store_in, value)?;
        }

        for (name, value) in private_values {
            let store_in = arguments.get(&name).ok_or_else(|| {
                LocalError::new(format!("Private argument {name} not found in the protocol signature"))
            })?;
            self.add_scalar(store_in, value)?;
        }

        Ok(())
    }

    pub fn new(
        id: SessionId<SP>,
        signer: SP::Signer,
        private_data: &P::PrivateData,
        shared_data: &P::SharedData,
    ) -> Result<Self, LocalError> {
        let verifier = signer.verifying_key();
        let output_node = make_tree::<SP, P>(&verifier, shared_data)?;
        let private_inputs = P::make_private_inputs(private_data);
        Self::new_inner(id, Some(signer), &verifier, output_node, private_inputs, shared_data)
    }

    pub(crate) fn new_with_reproduction_subtree(
        id: SessionId<SP>,
        subtree_root: &MappingTag,
        verifier: &SP::Verifier,
        shared_data: &P::SharedData,
    ) -> Result<Self, LocalError> {
        let output_node =
            make_tree::<SP, P>(verifier, shared_data)?.get_reproduction_subtree(subtree_root, verifier)?;
        Self::new_inner(id, None, verifier, output_node, PrivateInputs::new(), shared_data)
    }

    #[cfg(any(test, feature = "dev"))]
    pub fn new_with_replacements(
        id: SessionId<SP>,
        signer: SP::Signer,
        private_data: &P::PrivateData,
        shared_data: &P::SharedData,
        replacements: &[&Replacement<SP>],
    ) -> Result<Self, LocalError> {
        let verifier = signer.verifying_key();
        let mut output_node = make_tree::<SP, P>(&verifier, shared_data)?;
        for replacement in replacements {
            output_node = replacement.apply(output_node)?;
        }
        let private_inputs = P::make_private_inputs(private_data);
        Self::new_inner(id, Some(signer), &verifier, output_node, private_inputs, shared_data)
    }

    pub fn verifier(&self) -> &SP::Verifier {
        &self.verifier
    }

    fn add_scalar(&mut self, store_in: &ScalarTag, value: Value) -> Result<(), LocalError> {
        self.storage.set_scalar(store_in, value)?;
        self.ruleset.update_with_scalar_ready(store_in);
        Ok(())
    }

    fn add_element(&mut self, store_in: &MappingTag, id: &SP::Verifier, value: Value) -> Result<(), LocalError> {
        self.storage.set_elem(store_in, id, value)?;
        self.ruleset.update_with_element_ready(store_in, id);
        Ok(())
    }

    fn register_provable_error(&mut self, evidence: Evidence<SP, P>) {
        self.ruleset.update_with_banned_party(evidence.guilty_party());
        self.provable_errors.insert(evidence.guilty_party().clone(), evidence);
    }

    fn register_attributable_error(&mut self, guilty_party: SP::Verifier, tag: MappingTag) {
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
        let value = self.storage.get_scalar(task.output_tag())?;
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
        while let Some(action) = self.ruleset.pop_action()? {
            match action {
                Action::ReturnOutput(tag) => {
                    return Ok(Some(Task::finalize_with_success(tag)));
                }
                Action::Terminate(tag) => {
                    return Ok(Some(Task::finalize_with_stall(tag)));
                }
                Action::Send {
                    store_in,
                    to_send,
                    destination,
                } => {
                    let signed_value = self.storage.get_elem(&to_send, &destination)?;
                    return Ok(Some(Task::send(store_in, destination, signed_value)));
                }
                Action::ComputeScalar {
                    store_in,
                    function,
                    args,
                } => {
                    let arg_values = self.storage.get_scalar_args(args)?;
                    let args = Args::new(&self.data.id, self.verifier(), arg_values)?;
                    return Ok(Some(match function {
                        ScalarFunction::Infallible(function) => {
                            Task::compute_scalar_infallible(store_in, function, args)
                        }
                        ScalarFunction::InfallibleWithRng(function) => {
                            Task::compute_scalar_infallible_with_rng(store_in, function, args)
                        }
                    }));
                }
                Action::ComputeMappingElement {
                    store_in,
                    function,
                    index,
                    args,
                    on_error,
                } => {
                    let arg_values = self.storage.get_scalar_or_mapping_args(&index, args)?;
                    let args = Args::new(&self.data.id, self.verifier(), arg_values)?;
                    return Ok(Some(match function {
                        MappingFunction::Infallible(function) => {
                            Task::compute_mapping_elem_infallible(store_in, index, function, args)
                        }
                        MappingFunction::InfallibleWithRng(function) => {
                            Task::compute_mapping_elem_infallible_with_rng(store_in, index, function, args)
                        }
                        MappingFunction::SenderAttributable(function) => {
                            Task::compute_mapping_elem_sender_attributable(store_in, index, function, args, on_error)
                        }
                        MappingFunction::ThirdPartyAttributable { function, .. } => {
                            Task::compute_mapping_elem_third_party_attributable(store_in, index, function, args)
                        }
                    }));
                }
                Action::ComputeSerializeAndSignElement {
                    store_in,
                    function,
                    index,
                    data,
                    message_name,
                    serde_adapter,
                } => {
                    let signer = self
                        .signer
                        .as_ref()
                        .ok_or_else(|| LocalError::new("This session does not contain a signer"))?;
                    let value = match data {
                        AnyTag::Scalar(tag) => self.storage.get_scalar(&tag)?,
                        AnyTag::Mapping(tag) => self.storage.get_elem(&tag, &index)?,
                    };
                    let args = SerializeArgs::new(signer, &self.data, message_name, serde_adapter, value);
                    return Ok(Some(Task::compute_serialize_and_sign_elem(
                        store_in, index, function, args,
                    )));
                }
                Action::ComputeDeserializeElement {
                    store_in,
                    function,
                    index,
                    data,
                    serde_adapter,
                    on_error,
                } => {
                    let value = self.storage.get_elem(&data, &index)?;
                    let args = DeserializeArgs::new(&self.data, serde_adapter, value)?;
                    return Ok(Some(Task::compute_deserialize_elem(
                        store_in, index, function, args, on_error,
                    )));
                }
                Action::Collect {
                    store_in,
                    values,
                    indices,
                } => {
                    self.add_scalar(&store_in, self.storage.get_mapping_as_value(&values, &indices)?)?;
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
                        let evidence = EvidenceEnum::ConflictingMessages(ConflictingMessagesEvidence::new(
                            typed_existing_value,
                            typed_received_value,
                        ));
                        self.register_provable_error(Evidence::new(&self.data.id, &id, evidence));
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

                self.add_element(&store_in, &id, value)?;

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

    pub fn add_result(&mut self, result: TaskResult<SP>) -> Result<(), LocalError> {
        match result.into_enum() {
            TaskResultEnum::Send { store_in, destination } => {
                self.add_element(&store_in, &destination, Value::new(()))?;
            }
            TaskResultEnum::Compute { store_in, result } => {
                self.add_scalar(&store_in, result)?;
            }
            TaskResultEnum::ComputeMapping { store_in, id, result } => {
                self.add_element(&store_in, &id, result)?;
            }
            TaskResultEnum::SenderError { store_in, id, on_error } => match on_error {
                OnError::Escalate => self.register_attributable_error(id, store_in),
                OnError::CollectEvidence(message_names) => {
                    let mut signed_values = Vec::new();
                    for name in message_names {
                        let value = self
                            .storage
                            .get_elem(&MappingTag::signed_remote_with_full_name(&name), &id)?;
                        let signed_value = value.downcast_ref::<VerifiedValue<SP>>()?.clone().unverify();
                        signed_values.push(signed_value);
                    }
                    let evidence =
                        EvidenceEnum::SenderError(SenderErrorEvidence::new(&self.verifier, &store_in, signed_values));
                    self.register_provable_error(Evidence::new(&self.data.id, &id, evidence));
                }
            },
            TaskResultEnum::ThirdPartyError {
                store_in,
                id,
                associated_data,
            } => {
                let evidence = EvidenceEnum::ThirdPartyError(ThirdPartyErrorEvidence::new(
                    &self.verifier,
                    &store_in,
                    associated_data,
                ));
                self.register_provable_error(Evidence::new(&self.data.id, &id, evidence));
            }
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
