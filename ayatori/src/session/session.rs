use alloc::{collections::BTreeMap, format, sync::Arc, vec};
use core::{fmt::Debug, marker::PhantomData};

use signature::{Keypair, rand_core::CryptoRngCore};

use super::{
    message::{Message, SignedValue, VerificationError},
    ruleset::{Action, Arg, Ruleset},
    session_id::SessionId,
    storage::Storage,
};
use crate::{
    error::LocalError,
    protocol::{
        Args, ArrayFunction, ComputeError, ComputeErrorEnum, Erasable, ExecutableProtocol, ScalarFunction,
        SessionParameters, Tag, Value, WrappedArrayFunction, WrappedArrayFunctionPrivate, WrappedScalarFunction,
        WrappedScalarFunctionPrivate,
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

#[derive(Debug)]
pub struct TaskResult<Id>(TaskResultEnum<Id>);

#[derive(Debug)]
enum TaskResultEnum<Id> {
    Send { store_in: Tag, destination: Id },
    Compute { store_in: Tag, result: Value },
    ComputeArray { store_in: Tag, id: Id, result: Value },
    UnattributableError { store_in: Tag },
    AttributableError { store_in: Tag, id: Id },
}

#[derive(Debug, Clone, Copy)]
pub enum AddMessageResult {
    Success,
    InvalidSignature,
}

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
            return Ok(Some(Task::Finalize(FinalizeTask {
                outcome: self.storage.get(self.ruleset.output_tag())?,
            })));
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

                    return Ok(Some(Task::Send(SendTask {
                        store_in,
                        destination: destination.clone(),
                        signed_value,
                    })));
                }
                Action::ComputeScalar {
                    store_in,
                    function,
                    args,
                } => {
                    let arg_values = args
                        .iter()
                        .map(|(name, tag)| self.storage.get(tag).map(|value| (name.clone(), value)))
                        .collect::<Result<BTreeMap<_, _>, LocalError>>()?;
                    let args = Args::new(&self.signer, &self.id, &self.verifier(), arg_values)?;
                    match function {
                        ScalarFunction::Public(function) => {
                            return Ok(Some(Task::Compute(ComputeTask {
                                store_in,
                                function: ComputeFunction::Scalar { function },
                                args,
                            })));
                        }
                        ScalarFunction::Private(function) => {
                            return Ok(Some(Task::ComputeWithRng(ComputeWithRngTask {
                                store_in,
                                function: ComputeWithRngFunction::Scalar { function },
                                args,
                            })));
                        }
                    }
                }
                Action::ComputeArrayElement {
                    store_in,
                    function,
                    index,
                    args,
                } => {
                    let arg_values = args
                        .iter()
                        .map(|(name, arg)| match arg {
                            Arg::Scalar(tag) => self.storage.get(tag).map(|value| (name.clone(), value)),
                            Arg::ArrayElem(tag) => {
                                self.storage.get_elem(tag, &index).map(|value| (name.clone(), value))
                            }
                        })
                        .collect::<Result<BTreeMap<_, _>, LocalError>>()?;
                    let args = Args::new(&self.signer, &self.id, &self.verifier(), arg_values)?;
                    match function {
                        ArrayFunction::Public(function) => {
                            return Ok(Some(Task::Compute(ComputeTask {
                                store_in,
                                function: ComputeFunction::Array { function, id: index },
                                args,
                            })));
                        }
                        ArrayFunction::Private(function) => {
                            return Ok(Some(Task::ComputeWithRng(ComputeWithRngTask {
                                store_in,
                                function: ComputeWithRngFunction::Array { function, id: index },
                                args,
                            })));
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

    pub fn add_message(&mut self, message: Message<SP>) -> Result<AddMessageResult, LocalError> {
        for value in message.values() {
            let verified_value = match value.verify() {
                Ok(verified_value) => verified_value,
                Err(VerificationError::Local(error)) => return Err(error),
                Err(VerificationError::SignatureMismatch) => return Ok(AddMessageResult::InvalidSignature),
            };
            let source = verified_value.source().clone();
            let tag = Tag::signed_remote_with_full_name(verified_value.metadata().full_name());
            self.storage.set_elem(&tag, &source, Value::new(verified_value))?;
            self.ruleset.update_with_array_element_ready(&tag, &source);
        }
        Ok(AddMessageResult::Success)
    }

    pub fn add_result(&mut self, result: TaskResult<SP::Verifier>) -> Result<(), LocalError> {
        match result.0 {
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
