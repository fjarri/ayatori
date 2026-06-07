use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    fmt::{self, Display},
    marker::PhantomData,
};

use itertools::Itertools;
use signature::Keypair;

use super::{
    evidence::{
        ConflictingMessagesEvidence, Evidence, EvidenceKind, SenderErrorEvidence, SenderErrorWithRevealEvidence,
        ThirdPartyErrorEvidence,
    },
    storage::Storage,
    task::{
        DeserializeElementTask, ElementSenderAttributableTask, ElementSenderAttributableWithRevealTask,
        ElementThirdPartyAttributableTask, ElementUnattributableTask, PreprocessMessageTask,
        RngElementUnattributableTask, RngScalarUnattributableTask, ScalarUnattributableOptionalTask,
        ScalarUnattributableTask, SendTask, SerializeAndSignElementTask, SessionUpdate, SessionUpdateEnum, Task,
    },
};
#[cfg(feature = "dev")]
use crate::dev::Replacement;
use crate::{
    entities::{
        AnyTag, Args, AssociatedData, CollectedTag, ComputedScalarTag, DeserializeArgs, Erasable, EvidenceVerdict,
        MappingFunction, MappingTag, Message, MessageId, RemoteSignedTag, RuntimeError, ScalarFunction, ScalarTag,
        SerializeArgs, SessionId, SignedValue, SpuriousError, Value, VerifiedValue,
    },
    flat_representation::{Action, OnError, Ruleset, RulesetState},
    graph_representation::{AnyNode, ArgNodes, OutputNode, PartyBuildData, PrivateInputs, PublicInputs},
    traced_error::{Traceable, TraceableResult},
    traits::{ExecutableProtocol, SessionParameters},
};

#[derive_where::derive_where(Debug)]
pub(crate) struct SessionData<SP: SessionParameters> {
    pub(crate) id: SessionId<SP>,
    pub(crate) participants: BTreeSet<SP::Verifier>,
    pub(crate) local_participants: BTreeSet<SP::Verifier>,
}

/// A state of a protocol being executed.
#[derive_where::derive_where(Debug)]
pub struct Session<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    ruleset: Ruleset<SP>,
    storage: Storage<SP::Verifier>,
    signer: Option<Arc<SP::Signer>>,
    verifier: SP::Verifier,
    data: Arc<SessionData<SP>>,
    provable_errors: BTreeMap<SP::Verifier, Evidence<SP, P>>,
    attributable_errors: BTreeMap<SP::Verifier, String>,
    external_bans: BTreeMap<SP::Verifier, String>,
    preprocessing_tasks: Vec<PreprocessMessageTask<SP>>,
    phantom: PhantomData<fn() -> P>,
}

fn make_tree<SP, P>(verifier: &SP::Verifier, shared_data: &P::SharedData) -> Result<OutputNode<SP>, RuntimeError>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    let build_data = P::make_build_data(shared_data);
    let signature = P::signature();
    let arg_nodes = ArgNodes::new(&signature);
    let party_build_data = PartyBuildData::new(verifier);
    P::build(&party_build_data, &build_data, arg_nodes).map(Into::into)
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
        output_node: &OutputNode<SP>,
        private_inputs: PrivateInputs,
        shared_data: &P::SharedData,
    ) -> Result<Self, RuntimeError> {
        let participants = P::all_participants(shared_data);
        let local_participants = BTreeSet::from([verifier.clone()]);
        let public_inputs = P::make_public_inputs(shared_data);

        let ruleset = Ruleset::new(output_node, &private_inputs.names())
            .or_with_context(|| "Failed to build the ruleset".into())?;
        let storage = Storage::new();

        let data = Arc::new(SessionData {
            id,
            participants,
            local_participants,
        });
        let mut session = Self {
            ruleset,
            storage,
            signer: signer.map(Arc::new),
            verifier: verifier.clone(),
            data,
            provable_errors: BTreeMap::new(),
            attributable_errors: BTreeMap::new(),
            external_bans: BTreeMap::new(),
            preprocessing_tasks: Vec::new(),
            phantom: PhantomData,
        };

        session
            .fill_inputs(public_inputs, private_inputs)
            .or_with_context(|| "Failed to associate protocol inputs with the input nodes".into())?;

        Ok(session)
    }

    fn fill_inputs(&mut self, public_inputs: PublicInputs, private_inputs: PrivateInputs) -> Result<(), RuntimeError> {
        let arguments = self.ruleset.arguments().clone();

        let public_values = public_inputs.into_inner();
        let private_values = private_inputs.into_inner();

        let public_names = public_values.keys().collect::<BTreeSet<_>>();
        let private_names = private_values.keys().collect::<BTreeSet<_>>();

        if !public_names.is_disjoint(&private_names) {
            let mut intersection = public_names.intersection(&private_names);
            return Err(RuntimeError::new(format!(
                "Intersecting names in public and private arguments: {}",
                intersection.join(", ")
            )));
        }

        let arguments_given = public_names.union(&private_names).copied().collect::<BTreeSet<_>>();
        let arguments_required = arguments.keys().collect::<BTreeSet<_>>();

        // Note: we are allowing some arguments to be unused.

        if !arguments_required.is_subset(&arguments_given) {
            let missing_args = arguments_required.difference(&arguments_given).join(", ");
            return Err(RuntimeError::new(format!(
                "Some arguments required by the graph are not given: {missing_args}",
            )));
        }

        for (name, value) in public_values {
            if let Some(store_in) = arguments.get(&name) {
                self.add_scalar(&ScalarTag::Argument(store_in.clone()), value)
                    .or_with_context(|| format!("Failed to add the private input `{store_in}` to the storage"))?;
            }
        }

        for (name, value) in private_values {
            if let Some(store_in) = arguments.get(&name) {
                self.add_scalar(&ScalarTag::Argument(store_in.clone()), value)
                    .or_with_context(|| format!("Failed to add the public input `{store_in}` to the storage"))?;
            }
        }

        Ok(())
    }

    /// Creates a new session with the given party identity (signer), and session ID.
    pub fn new(
        id: SessionId<SP>,
        signer: SP::Signer,
        private_data: &P::PrivateData,
        shared_data: &P::SharedData,
    ) -> Result<Self, RuntimeError> {
        let verifier = signer.verifying_key();
        let output_node = make_tree::<SP, P>(&verifier, shared_data)
            .or_with_context(|| "Failed to build the protocol graph".into())?;
        let private_inputs = P::make_private_inputs(private_data);
        Self::new_inner(id, Some(signer), &verifier, &output_node, private_inputs, shared_data)
    }

    pub(crate) fn new_with_reproduction_subtree(
        id: SessionId<SP>,
        subtree_root: &MappingTag,
        reported_by: &SP::Verifier,
        guilty_party: &SP::Verifier,
        shared_data: &P::SharedData,
        associated_data: Option<&AssociatedData<SP>>,
    ) -> Result<Self, RuntimeError> {
        let full_graph = make_tree::<SP, P>(reported_by, shared_data)
            .or_with_context(|| "Failed to build the protocol graph".into())?;
        let output_node = AnyNode::from(full_graph)
            .get_reproduction_subtree(subtree_root, guilty_party, associated_data)
            .or_with_context(|| format!("Failed to extract the reproduction subtree for node `{subtree_root}`"))?;
        Self::new_inner(id, None, reported_by, &output_node, PrivateInputs::new(), shared_data)
    }

    /// Creates a new session applying some replacements to the node graph (for testing purposes).
    #[cfg(feature = "dev")]
    pub fn new_with_replacements(
        id: SessionId<SP>,
        signer: SP::Signer,
        private_data: &P::PrivateData,
        shared_data: &P::SharedData,
        replacements: &[&Replacement<SP>],
    ) -> Result<Self, RuntimeError> {
        let verifier = signer.verifying_key();
        let mut output_node = make_tree::<SP, P>(&verifier, shared_data)
            .or_with_context(|| "Failed to build the protocol graph".into())?;
        for replacement in replacements {
            output_node = replacement.apply(&output_node).or_with_context(|| {
                format!(
                    "Failed to build apply the replacement for node `{}`",
                    output_node.store_in()
                )
            })?;
        }
        let private_inputs = P::make_private_inputs(private_data);
        Self::new_inner(id, Some(signer), &verifier, &output_node, private_inputs, shared_data)
    }

    /// Returns the identity of the party associated with the session.
    pub fn verifier(&self) -> &SP::Verifier {
        &self.verifier
    }

    fn add_scalar(&mut self, store_in: &ScalarTag, value: Value) -> Result<(), RuntimeError> {
        self.storage
            .set_scalar(store_in, value)
            .or_with_context(|| format!("Failed to store the scalar result of `{store_in}`"))?;
        self.ruleset.update_with_scalar_ready(store_in);
        Ok(())
    }

    fn add_element(&mut self, store_in: &MappingTag, id: &SP::Verifier, value: Value) -> Result<(), RuntimeError> {
        self.storage
            .set_elem(store_in, id, value)
            .or_with_context(|| format!("Failed to store a mapping element result of `{store_in}`"))?;
        self.ruleset.update_with_element_ready(store_in, id);
        Ok(())
    }

    fn register_provable_error(&mut self, evidence: Evidence<SP, P>) {
        self.ruleset.update_with_banned_party(evidence.guilty_party());
        self.provable_errors.insert(evidence.guilty_party().clone(), evidence);
    }

    fn register_send_error(&mut self, guilty_party: SP::Verifier) {
        self.ruleset.update_with_banned_party(&guilty_party);
        self.attributable_errors
            .insert(guilty_party, "Error when sending a message".into());
    }

    fn register_attributable_error(&mut self, guilty_party: SP::Verifier, tag: &MappingTag) {
        self.ruleset.update_with_banned_party(&guilty_party);
        self.attributable_errors
            .insert(guilty_party, format!("Error when calculating {tag}"));
    }

    fn register_banned_party(&mut self, guilty_party: SP::Verifier, reason: String) {
        self.ruleset.update_with_banned_party(&guilty_party);
        self.external_bans.insert(guilty_party, reason);
    }

    fn make_report(self, outcome: SessionOutcome<SP, P>) -> SessionReport<SP, P> {
        SessionReport::<SP, P> {
            outcome,
            provable_errors: self.provable_errors,
            attributable_errors: self.attributable_errors,
            external_bans: self.external_bans,
        }
    }

    pub(crate) fn get_output<T: Erasable + Clone>(&self, output_tag: &ComputedScalarTag) -> Result<T, RuntimeError> {
        let tag = ScalarTag::Computed(output_tag.clone());
        let value = self
            .storage
            .get_scalar(&tag)
            .or_with_context(|| "Failed to get the output value from storage".into())?;
        value
            .downcast::<T>()
            .or_with_context(|| "Failed to downcast the output value".into())
    }

    pub(crate) fn finalize_with_evidence_verdict(self) -> Result<EvidenceVerdict, RuntimeError> {
        self.get_output::<EvidenceVerdict>(self.ruleset.output_tag())
            .or_with_context(|| "Failed to extract the evidence verdict".into())
    }

    fn finalize_with_success(self) -> Result<SessionReport<SP, P>, RuntimeError> {
        let result = self.get_output::<P::Output>(self.ruleset.output_tag())?;
        Ok(self.make_report(SessionOutcome::Success(result)))
    }

    /// Terminates the session and returns the report containing the recorded failures of remote parties (if any).
    pub fn terminate(self) -> SessionReport<SP, P> {
        self.make_report(SessionOutcome::ManuallyTerminated)
    }

    /// Registers a received message.
    fn add_message(&mut self, message_id: &MessageId<SP>, message: Message<SP>) {
        let tasks = message
            .into_values()
            .into_iter()
            .map(|signed_value| PreprocessMessageTask::new(&self.data, message_id.clone(), signed_value))
            .collect::<Vec<_>>();
        self.preprocessing_tasks.extend(tasks);
    }

    /// Attempts to make a task to execute.
    ///
    /// The returned task may be offloaded to a thread pool.
    pub fn make_task(&mut self) -> Result<Option<Task<SP>>, RuntimeError> {
        if let Some(task) = self.preprocessing_tasks.pop() {
            return Ok(Some(task.into()));
        }

        while let Some(action) = self.ruleset.pop_action() {
            match action {
                Action::DirectMessage {
                    store_in,
                    to_send,
                    destination,
                } => {
                    let value = self
                        .storage
                        .get_elem(&MappingTag::LocalSigned(to_send), &destination)
                        .or_with_context(|| format!("Failed to get the argument for `{store_in}` from storage"))?;
                    let signed_value = value
                        .downcast::<SignedValue<SP>>()
                        .or_with_context(|| "Failed to downcast the value to be sent".into())?;
                    let message = Message::new(vec![signed_value])?;
                    return Ok(Some(SendTask::new(store_in, destination, message).into()));
                }
                Action::ComputeScalar {
                    store_in,
                    function,
                    args,
                } => {
                    let arg_values = self
                        .storage
                        .get_scalar_args(args)
                        .or_with_context(|| format!("Failed to get the arguments for `{store_in}` from storage"))?;
                    let args = Args::new(&self.data.id, self.verifier(), arg_values);
                    return Ok(Some(match function {
                        ScalarFunction::Unattributable(function) => {
                            ScalarUnattributableTask::new(store_in, function, args).into()
                        }
                        ScalarFunction::UnattributableOptional(function) => {
                            ScalarUnattributableOptionalTask::new(store_in, function, args).into()
                        }
                        ScalarFunction::UnattributableWithRng(function) => {
                            RngScalarUnattributableTask::new(store_in, function, args).into()
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
                    let arg_values = self
                        .storage
                        .get_scalar_or_mapping_args(&index, args)
                        .or_with_context(|| format!("Failed to get the arguments for `{store_in}` from storage"))?;
                    let args = Args::new(&self.data.id, self.verifier(), arg_values);
                    return Ok(Some(match function {
                        MappingFunction::Unattributable(function) => {
                            ElementUnattributableTask::new(store_in, function, index, args).into()
                        }
                        MappingFunction::UnattributableWithRng(function) => {
                            RngElementUnattributableTask::new(store_in, function, index, args).into()
                        }
                        MappingFunction::SenderAttributable(function) => {
                            ElementSenderAttributableTask::new(store_in, function, index, args, on_error).into()
                        }
                        MappingFunction::SenderAttributableWithReveal(function) => {
                            ElementSenderAttributableWithRevealTask::new(store_in, function, index, args, on_error)
                                .into()
                        }
                        MappingFunction::ThirdPartyAttributable(function) => {
                            ElementThirdPartyAttributableTask::new(store_in, function, index, args).into()
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
                    let signer = self.signer.as_ref().ok_or_else(|| {
                        // This can happen if a serialization node somehow remains
                        // in an evidence verification subtree.
                        RuntimeError::new(
                            "Attempted to execute a serialize-and-sign node in a session without a signer",
                        )
                    })?;

                    let value = match data {
                        AnyTag::Scalar(tag) => self.storage.get_scalar(&tag),
                        AnyTag::Mapping(tag) => self.storage.get_elem(&tag, &index),
                    }
                    .or_with_context(|| format!("Failed to get the argument for `{store_in}` from storage"))?;

                    let args = SerializeArgs::new(signer, &self.data.id, message_name, serde_adapter, value);
                    return Ok(Some(
                        SerializeAndSignElementTask::new(store_in, function, index, args).into(),
                    ));
                }
                Action::ComputeDeserializeElement {
                    store_in,
                    function,
                    index,
                    data,
                    serde_adapter,
                    expected_senders,
                    on_error,
                } => {
                    let value = self
                        .storage
                        .get_elem(&MappingTag::RemoteSigned(data), &index)
                        .or_with_context(|| format!("Failed to get the argument for `{store_in}` from storage"))?;
                    let args = DeserializeArgs::new(&expected_senders, serde_adapter, value);
                    return Ok(Some(
                        DeserializeElementTask::new(store_in, function, index, args, on_error).into(),
                    ));
                }
                Action::MergeScalar { store_in, left, right } => {
                    self.add_scalar(
                        &ScalarTag::Merged(store_in.clone()),
                        self.storage
                            .get_one_or_both_as_value(&left, &right)
                            .or_with_context(|| format!("Failed to get the argument for `{store_in}` from storage"))?,
                    )?;
                }
                Action::Collect {
                    store_in,
                    values,
                    indices,
                } => {
                    self.add_scalar(
                        &ScalarTag::Collected(store_in.clone()),
                        self.storage
                            .get_mapping_as_value(&values, &indices)
                            .or_with_context(|| format!("Failed to get the argument for `{store_in}` from storage"))?,
                    )?;
                }
            }
        }

        Ok(None)
    }

    /// Registers the result of an executed task.
    pub fn with_update(mut self, result: SessionUpdate<SP>) -> Result<SessionState<SP, P>, RuntimeError> {
        let new_state = self.with_update_inner(result)?;
        Ok(match new_state {
            AddSessionUpdate::StateChanged => {
                let state = self.ruleset.state().clone();
                match state {
                    RulesetState::InProgress => SessionState::InProgress(self),
                    RulesetState::ReachedOutput => SessionState::ReachedOutput(ReachedOutputSession(self)),
                    RulesetState::ImpossibleToCollect(tags) => {
                        let report = self.make_report(SessionOutcome::Unfinishable(UnfinishableOutcome(tags)));
                        SessionState::Unfinishable(report)
                    }
                }
            }
            AddSessionUpdate::StateDidNotChange => SessionState::InProgress(self),
            AddSessionUpdate::MessageAttributableError(error) => {
                SessionState::InProgressWithMessageError { session: self, error }
            }
            AddSessionUpdate::SpuriousError { store_in, error } => {
                let report = self.make_report(SessionOutcome::SpuriousError(SpuriousErrorOutcome { store_in, error }));
                SessionState::Unfinishable(report)
            }
        })
    }

    /// Registers the result of an executed task.
    fn with_update_inner(&mut self, result: SessionUpdate<SP>) -> Result<AddSessionUpdate<SP>, RuntimeError> {
        match result.into_inner() {
            SessionUpdateEnum::NoActionNeeded => Ok(AddSessionUpdate::StateDidNotChange),
            SessionUpdateEnum::Received { id, message } => {
                self.add_message(&id, message);
                Ok(AddSessionUpdate::StateDidNotChange)
            }
            SessionUpdateEnum::RuntimeError(error) => Err(error.with_context("Task returned a runtime error")),
            SessionUpdateEnum::SpuriousError { store_in, error } => {
                Ok(AddSessionUpdate::SpuriousError { store_in, error })
            }
            SessionUpdateEnum::Sent { store_in, destination } => {
                self.add_element(&store_in, &destination, Value::new(()))?;
                Ok(AddSessionUpdate::StateChanged)
            }
            SessionUpdateEnum::ComputedScalar { store_in, result } => {
                self.add_scalar(&store_in, result)?;
                Ok(AddSessionUpdate::StateChanged)
            }
            SessionUpdateEnum::ComputedMappingElement {
                store_in,
                index,
                result,
            } => {
                self.add_element(&store_in, &index, result)?;
                Ok(AddSessionUpdate::StateChanged)
            }
            SessionUpdateEnum::SenderError {
                store_in,
                guilty_party,
                error,
                on_error,
            } => match on_error {
                OnError::Escalate => {
                    self.register_attributable_error(guilty_party, &store_in);
                    Ok(AddSessionUpdate::StateChanged)
                }
                OnError::CollectEvidence(message_names) => {
                    let mut signed_values = Vec::new();
                    for name in message_names {
                        let value = self
                            .storage
                            .get_elem(
                                &MappingTag::RemoteSigned(RemoteSignedTag::new_with_full_name(&name)),
                                &guilty_party,
                            )
                            .or_with_context(|| {
                                format!(
                                    concat!(
                                        "Failed to get the signed message `{}` ",
                                        "to attach to the evidence of `{}` failure"
                                    ),
                                    name, store_in
                                )
                            })?;
                        let signed_value = value
                            .downcast_ref::<VerifiedValue<SP>>()
                            .or_with_context(|| {
                                format!(
                                    concat!(
                                        "Failed to downcast the signed message `{}` ",
                                        "to attach to the evidence of `{}` failure"
                                    ),
                                    name, store_in
                                )
                            })?
                            .clone()
                            .unverify();
                        signed_values.push(signed_value);
                    }
                    let evidence = EvidenceKind::SenderError(SenderErrorEvidence::new(
                        &self.verifier,
                        &store_in,
                        signed_values,
                        error,
                    ));
                    self.register_provable_error(Evidence::new(&self.data.id, &guilty_party, evidence));
                    Ok(AddSessionUpdate::StateChanged)
                }
            },
            SessionUpdateEnum::SenderErrorWithReveal {
                store_in,
                guilty_party,
                error,
                on_error,
            } => match on_error {
                OnError::Escalate => {
                    self.register_attributable_error(guilty_party, &store_in);
                    Ok(AddSessionUpdate::StateChanged)
                }
                OnError::CollectEvidence(message_names) => {
                    let mut signed_values = Vec::new();
                    for name in message_names {
                        let value = self
                            .storage
                            .get_elem(
                                &MappingTag::RemoteSigned(RemoteSignedTag::new_with_full_name(&name)),
                                &guilty_party,
                            )
                            .or_with_context(|| {
                                format!(
                                    concat!(
                                        "Failed to get the signed message `{}` ",
                                        "to attach to the evidence of `{}` failure"
                                    ),
                                    name, store_in
                                )
                            })?;
                        let signed_value = value
                            .downcast_ref::<VerifiedValue<SP>>()
                            .or_with_context(|| {
                                format!(
                                    concat!(
                                        "Failed to downcast the signed message `{}` ",
                                        "to attach to the evidence of `{}` failure"
                                    ),
                                    name, store_in
                                )
                            })?
                            .clone()
                            .unverify();
                        signed_values.push(signed_value);
                    }
                    let evidence = EvidenceKind::SenderErrorWithReveal(SenderErrorWithRevealEvidence::new(
                        &self.verifier,
                        &store_in,
                        signed_values,
                        error,
                    ));
                    self.register_provable_error(Evidence::new(&self.data.id, &guilty_party, evidence));
                    Ok(AddSessionUpdate::StateChanged)
                }
            },
            SessionUpdateEnum::ThirdPartyError { store_in, error } => {
                let (guilty_party, error) = error.unpack();
                let evidence =
                    EvidenceKind::ThirdPartyError(ThirdPartyErrorEvidence::new(&self.verifier, &store_in, error));
                self.register_provable_error(Evidence::new(&self.data.id, &guilty_party, evidence));
                Ok(AddSessionUpdate::StateChanged)
            }
            SessionUpdateEnum::Preprocessed {
                store_in,
                source,
                value,
            } => {
                if let Ok(existing_value) = self.storage.get_elem(&store_in, &source) {
                    let typed_existing_value = existing_value
                        .downcast_ref::<VerifiedValue<SP>>()
                        .or_with_context(|| format!("Failed to downcast a stored signed message `{store_in}`"))?;
                    let typed_received_value = value
                        .downcast_ref::<VerifiedValue<SP>>()
                        .or_with_context(|| format!("Failed to downcast a newly received message `{store_in}`"))?;

                    // Both values are signed, contain the same named value, but are different.
                    // This is a provable failure.
                    // Note that the payload or metadata of either value may still be invalid
                    // (it is possible that it has not been checked yet at this point),
                    // but it does not matter since we already got our evidence.
                    if typed_existing_value.metadata() != typed_received_value.metadata()
                        || typed_existing_value.serialized_value() != typed_received_value.serialized_value()
                    {
                        let evidence = EvidenceKind::ConflictingMessages(ConflictingMessagesEvidence::new(
                            typed_existing_value,
                            typed_received_value,
                        ));
                        self.register_provable_error(Evidence::new(&self.data.id, &source, evidence));
                        return Ok(AddSessionUpdate::StateChanged);
                    }

                    // The message is a duplicate, we cannot do anything at this point.
                    // If the payload/metadata are invalid, the later checks will produce verifiable evidence.
                    // For now we can only report both message IDs that delivered these values,
                    // and let the user deal with it, if possible.
                    let error = MessageAttributableError::DuplicateMessages(DuplicateMessagesError {
                        first: typed_existing_value.message_id().clone(),
                        second: typed_existing_value.message_id().clone(),
                    });
                    return Ok(AddSessionUpdate::MessageAttributableError(error));
                }

                self.add_element(&store_in, &source, value)?;
                Ok(AddSessionUpdate::StateChanged)
            }
            SessionUpdateEnum::MessageError {
                message_id,
                description,
            } => {
                let error = MessageAttributableError::InvalidMessage(InvalidMessageError {
                    message_id,
                    description,
                });
                Ok(AddSessionUpdate::MessageAttributableError(error))
            }
            SessionUpdateEnum::SendError { destination } => {
                self.register_send_error(destination);
                Ok(AddSessionUpdate::StateChanged)
            }
            SessionUpdateEnum::ExternalBan { party_id, reason } => {
                self.register_banned_party(party_id, reason);
                Ok(AddSessionUpdate::StateChanged)
            }
        }
    }
}

/// A wrapper for a session that has reached the output.
#[derive_where::derive_where(Debug)]
pub struct ReachedOutputSession<SP: SessionParameters, P: ExecutableProtocol<SP>>(Session<SP, P>);

impl<SP, P> ReachedOutputSession<SP, P>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    /// Destroys the session and returns the report containing the output
    /// and recorded failures of remote parties (if any).
    pub fn finalize(self) -> Result<SessionReport<SP, P>, RuntimeError> {
        self.0.finalize_with_success()
    }

    pub(crate) fn finalize_with_evidence_verdict(self) -> Result<EvidenceVerdict, RuntimeError> {
        self.0.finalize_with_evidence_verdict()
    }

    /// Returns the contained session allowing to continue with the event loop.
    ///
    /// Can be used to accumulate more shares for protocols with threshold conditions.
    pub fn continue_execution(self) -> Session<SP, P> {
        self.0
    }
}

impl<SP, P> AsRef<Session<SP, P>> for ReachedOutputSession<SP, P>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    fn as_ref(&self) -> &Session<SP, P> {
        &self.0
    }
}

/// Possible results of attempting to finalize a session.
#[derive_where::derive_where(Debug)]
pub enum SessionState<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    /// The session is in progress.
    ///
    /// Continue working with the returned session object.
    InProgress(Session<SP, P>),
    /// The session is in progress, but a message-attributable error was registered.
    ///
    /// Continue working with the returned session object,
    /// and handle the error according to what your transport level allows.
    InProgressWithMessageError {
        /// The session in progress.
        session: Session<SP, P>,
        /// The message-attributable error.
        error: MessageAttributableError<SP>,
    },
    /// The session has reached the output.
    ReachedOutput(ReachedOutputSession<SP, P>),
    /// The session is unfinishable due to some nodes having been banned.
    Unfinishable(SessionReport<SP, P>),
}

/// An error that is attributable to a specific message, but not to a specific party.
#[derive_where::derive_where(Debug)]
#[derive(displaydoc::Display)]
pub enum MessageAttributableError<SP: SessionParameters> {
    /// A registered message was found to be invalid.
    #[displaydoc("{0}")]
    InvalidMessage(InvalidMessageError<SP>),
    /// A registered message was found to be a duplicate of a previously registered message.
    #[displaydoc("{0}")]
    DuplicateMessages(DuplicateMessagesError<SP>),
}

impl<SP: SessionParameters> core::error::Error for MessageAttributableError<SP> {}

/// A registered message was found to be invalid.
#[derive_where::derive_where(Debug)]
#[derive(displaydoc::Display)]
#[displaydoc("Invalid message with ID {message_id:?}: {description}")]
pub struct InvalidMessageError<SP: SessionParameters> {
    /// The message's ID.
    ///
    /// The user may possess the means of attributing it to a specific party,
    /// in which case it should be penalized.
    pub message_id: MessageId<SP>,
    /// The description of the error.
    pub description: String,
}

impl<SP: SessionParameters> core::error::Error for InvalidMessageError<SP> {}

/// A registered message was found to be a duplicate of a previously registered message.
#[derive_where::derive_where(Debug)]
#[derive(displaydoc::Display)]
#[displaydoc("Duplicate data in messages with IDs {first:?} and {second:?}")]
pub struct DuplicateMessagesError<SP: SessionParameters> {
    /// The first message's ID.
    ///
    /// The user may possess the means of attributing it to a specific party,
    /// in which case it should be penalized.
    pub first: MessageId<SP>,
    /// The second message's ID.
    ///
    /// The user may possess the means of attributing it to a specific party,
    /// in which case it should be penalized.
    pub second: MessageId<SP>,
}

impl<SP: SessionParameters> core::error::Error for DuplicateMessagesError<SP> {}

/// The results of a session.
#[derive_where::derive_where(Debug, Clone)]
pub struct SessionReport<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    /// The session's outcome.
    pub outcome: SessionOutcome<SP, P>,
    /// The provable attributable errors registered during the execution.
    pub provable_errors: BTreeMap<SP::Verifier, Evidence<SP, P>>,
    /// The unprovable attributable errors registered during the execution.
    pub attributable_errors: BTreeMap<SP::Verifier, String>,
    /// The bans requested by the user explicitly.
    pub external_bans: BTreeMap<SP::Verifier, String>,
}

impl<SP: SessionParameters, P: ExecutableProtocol<SP>> SessionReport<SP, P> {
    /// Returns the protocol's output if the session was successful.
    pub fn success(self) -> Option<P::Output> {
        if let SessionOutcome::Success(output) = self.outcome {
            Some(output)
        } else {
            None
        }
    }

    /// Returns a reference to the protocol's output if the session was successful.
    pub fn success_ref(&self) -> Option<&P::Output> {
        if let SessionOutcome::Success(output) = &self.outcome {
            Some(output)
        } else {
            None
        }
    }
}

/// Possible session outcomes.
#[derive_where::derive_where(Debug, Clone)]
#[derive(displaydoc::Display)]
pub enum SessionOutcome<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    /// Reached the output successfully.
    #[displaydoc("Success: {0:?}")]
    Success(P::Output),
    /// Was terminated via [`Session::terminate`].
    #[displaydoc("Manually terminated")]
    ManuallyTerminated,
    /// Some collect nodes are impossible to finish due to some parties having been banned.
    #[displaydoc("Unfinishable: {0}")]
    Unfinishable(UnfinishableOutcome),
    /// A [`SpuriousError`] error occurred in one of the computations.
    #[displaydoc("Spurious error: {0}")]
    SpuriousError(SpuriousErrorOutcome),
}

enum AddSessionUpdate<SP: SessionParameters> {
    StateChanged,
    StateDidNotChange,
    MessageAttributableError(MessageAttributableError<SP>),
    SpuriousError { store_in: AnyTag, error: SpuriousError },
}

/// Contains the specifics about why the session was impossible to finalize.
#[derive(Debug, Clone)]
pub struct UnfinishableOutcome(Vec<CollectedTag>);

impl Display for UnfinishableOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Impossible to collect: {}", self.0.iter().join(", "))
    }
}

/// Contains the specifics about why the session was impossible to finalize.
#[derive(Debug, Clone)]
pub struct SpuriousErrorOutcome {
    store_in: AnyTag,
    error: SpuriousError,
}

impl Display for SpuriousErrorOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Spurious error when calculating {}: {}", self.store_in, self.error)
    }
}
