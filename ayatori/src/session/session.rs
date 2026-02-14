use alloc::{format, sync::Arc};
use core::{fmt::Debug, marker::PhantomData};

use signature::Keypair;

use super::{
    message::VerifiedMessage,
    ruleset::{Action, Ruleset},
    session_id::SessionId,
    storage::Storage,
    task::{Task, TaskResult, TaskResultEnum},
};
use crate::{
    error::LocalError,
    protocol::{Args, ArrayFunction, ExecutableProtocol, ScalarFunction, SessionParameters, Tag, Value},
};

// TODO: do we need to be generic over P here?
#[derive(Debug)]
pub struct Session<SP: SessionParameters, P: ExecutableProtocol<SP>> {
    id: SessionId<SP>,
    signer: Arc<SP::Signer>,
    ruleset: Ruleset<SP>,
    storage: Storage<SP::Verifier>,
    phantom: PhantomData<P>,
}

impl<SP, P> Session<SP, P>
where
    SP: SessionParameters,
    P: ExecutableProtocol<SP>,
{
    pub fn new(id: SessionId<SP>, signer: SP::Signer, shared_data: &P::SharedData) -> Result<Self, LocalError> {
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

    pub fn add_message(&mut self, message: VerifiedMessage<SP>) -> Result<(), LocalError> {
        for value in message.values() {
            let source = value.source().clone();
            let tag = Tag::signed_remote_with_full_name(value.metadata().full_name());
            self.storage.set_elem(&tag, &source, Value::new(value))?;
            self.ruleset.update_with_array_element_ready(&tag, &source);
        }
        Ok(())
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
