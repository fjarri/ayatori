use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
};
use core::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};
use signature::Keypair;

use super::{
    evidence::{ConflictingMessagesEvidence, Evidence, SenderErrorEvidence},
    message::{MessageId, MessageWithId, SignedValue, VerifiedValue},
    ruleset::{Action, Ruleset},
    session_id::SessionId,
    storage::Storage,
    task::{
        FinalizeWithSuccessToken, PreprocessingResult, PreprocessingResultEnum, PreprocessingTask, Task, TaskResult,
        TaskResultEnum,
    },
};
use crate::{
    error::LocalError,
    protocol::{
        Args, ArrayFunction, Dependencies, ExecutableProtocol, FullName, Node, NodeKind, ProtocolArgs, Reproducibility,
        ScalarFunction, SessionParameters, Tag, Value,
    },
};

#[derive(Debug)]
pub(crate) struct SessionData<SP: SessionParameters> {
    pub(crate) id: SessionId<SP>,
    pub(crate) signer: SP::Signer,
    pub(crate) participants: BTreeSet<SP::Verifier>,
    pub(crate) local_participants: BTreeSet<SP::Verifier>,
    pub(crate) expected_messages: BTreeMap<FullName, BTreeSet<SP::Verifier>>,
}

// TODO: do we need to be generic over P here?
#[derive(Debug)]
pub struct Session<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    ruleset: Ruleset<SP>,
    storage: Storage<SP::Verifier>,
    data: Arc<SessionData<SP>>,
    provable_errors: BTreeMap<SP::Verifier, Evidence<SP, P>>,
    attributable_errors: BTreeMap<SP::Verifier, String>,
    nodes: BTreeMap<Tag, Node<SP>>,
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
        let participants = P::all_participants(shared_data);
        let local_participants = BTreeSet::from([signer.verifying_key()]);
        let public_inputs = P::make_public_inputs(shared_data);
        let private_inputs = P::make_private_inputs(private_data);
        let protocol_args = ProtocolArgs::new_from_inputs(private_inputs, public_inputs)?;
        let build_data = P::make_build_data(shared_data);
        let output_node = P::build(&signer.verifying_key(), &build_data, protocol_args)?;

        // TODO: or just save Reproducibility?
        let nodes = output_node
            .flattened(None, Dependencies::All)
            .into_iter()
            .map(|node| (node.store_in().clone(), node))
            .collect();

        let ruleset = Ruleset::new(&output_node)?;
        let expected_messages = ruleset.expected_messages().clone();
        let storage = Storage::new();
        let data = Arc::new(SessionData {
            id,
            signer,
            participants,
            local_participants,
            expected_messages,
        });
        Ok(Self {
            ruleset,
            storage,
            data,
            provable_errors: BTreeMap::new(),
            attributable_errors: BTreeMap::new(),
            nodes,
            phantom: PhantomData,
        })
    }

    pub fn verifier(&self) -> SP::Verifier {
        self.data.signer.verifying_key()
    }

    fn register_provable_error(&mut self, evidence: Evidence<SP, P>) {
        self.provable_errors.insert(evidence.guilty_party().clone(), evidence);
        // TODO: remove all affected rules
    }

    fn register_attributable_error(&mut self, guilty_party: SP::Verifier, tag: Tag) {
        self.attributable_errors
            .insert(guilty_party, format!("Error when calculating {tag}"));
        // TODO: remove all affected rules
    }

    fn make_report(self) -> SessionReport<SP, P> {
        SessionReport::<SP, P> {
            provable_errors: self.provable_errors,
            attributable_errors: self.attributable_errors,
        }
    }

    pub fn finalize_with_success(
        self,
        _token: FinalizeWithSuccessToken,
    ) -> Result<(P::Output, SessionReport<SP, P>), LocalError> {
        let value = self.storage.get(self.ruleset.output_tag())?;
        let result = value.downcast::<P::Output>()?;
        Ok((result, self.make_report()))
    }

    pub fn make_task(&mut self) -> Result<Option<Task<SP>>, LocalError> {
        if self.storage.contains(self.ruleset.output_tag()) {
            return Ok(Some(Task::finalize_with_success()));
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
                    let args = Args::new(store_in.full_name(), &self.data, &self.verifier(), arg_values)?;
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
                    ..
                } => {
                    let arg_values = self.storage.get_scalar_or_array_args(&index, args)?;
                    let args = Args::new(store_in.full_name(), &self.data, &self.verifier(), arg_values)?;
                    return Ok(Some(match function {
                        ArrayFunction::Infallible(function) => {
                            Task::compute_array_elem_infallible(store_in, index, function, args)
                        }
                        ArrayFunction::InfallibleWithRng(function) => {
                            Task::compute_array_elem_infallible_with_rng(store_in, index, function, args)
                        }
                        ArrayFunction::SenderAttributable(function) => {
                            Task::compute_array_elem_sender_attributable(store_in, index, function, args)
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

    pub fn preprocess_message(&self, message: MessageWithId<SP>) -> impl Iterator<Item = PreprocessingTask<SP>> {
        let message_id = message.id().clone();
        message
            .into_values()
            .map(move |value| PreprocessingTask::new(&self.data, message_id.clone(), value))
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
            TaskResultEnum::SenderError { store_in, id } => {
                let node = self.nodes.get(&store_in).unwrap();
                // TODO: this is quite fragile.
                // Ideally we would want to do that at session creation time.
                match node.reproducibility() {
                    Reproducibility::Available(leaf_nodes) => {
                        let mut signed_values = BTreeMap::new();
                        for node in leaf_nodes {
                            match node.kind() {
                                NodeKind::Receive { .. } => {
                                    let value = self.storage.get_elem(node.store_in(), &id)?;
                                    let signed_value = value.downcast_ref::<SignedValue<SP>>()?;
                                    signed_values.insert(node.store_in().clone(), signed_value.clone());
                                }
                                // TODO: if we hit a private value here, we need to fall back to
                                // registering an attributable error.
                                _ => {}
                            }
                        }
                        let evidence = Evidence::SenderError(SenderErrorEvidence::new(
                            &id,
                            &self.data.signer.verifying_key(),
                            &store_in,
                            signed_values,
                        ));
                        self.register_provable_error(evidence);
                    }
                    Reproducibility::NotAvailable => {
                        self.register_attributable_error(id, store_in);
                    }
                }
            }
            TaskResultEnum::ThirdPartyError { .. } => todo!(),
        }
        Ok(())
    }
}

#[derive(Debug)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    pub provable_errors: BTreeMap<SP::Verifier, Evidence<SP, P>>,
    pub attributable_errors: BTreeMap<SP::Verifier, String>,
}
