use alloc::{collections::BTreeMap, format, sync::Arc, vec};
use core::fmt::Debug;

use signature::{Keypair, rand_core::CryptoRngCore};

use super::{
    message::{Message, SignedValue, VerificationError},
    ruleset::{Action, Arg, Ruleset},
};
use crate::{
    error::LocalError,
    protocol::{
        Args, ArrayFunction, ComputeError, Erasable, PartyId, Protocol, ScalarFunction, SessionParameters, Tag, Value,
        WrappedArrayFunction, WrappedArrayFunctionPrivate, WrappedScalarFunction, WrappedScalarFunctionPrivate,
    },
};

#[derive(Debug)]
struct Storage<Id> {
    scalars: BTreeMap<Tag, Value>,
    mappings: BTreeMap<Tag, BTreeMap<Id, Value>>,
}

impl<Id: PartyId> Storage<Id> {
    fn new() -> Self {
        Self {
            scalars: BTreeMap::new(),
            mappings: BTreeMap::new(),
        }
    }

    fn contains(&self, tag: &Tag) -> bool {
        self.scalars.contains_key(tag)
    }

    fn get(&self, tag: &Tag) -> Result<Value, LocalError> {
        Ok(self
            .scalars
            .get(tag)
            .ok_or_else(|| LocalError::new(format!("Scalar {tag} not found in storage")))?
            .clone())
    }

    fn set(&mut self, tag: &Tag, value: Value) -> Result<(), LocalError> {
        match self.scalars.insert(tag.clone(), value) {
            None => Ok(()),
            Some(_) => Err(LocalError::new(format!("Scalar {tag} already has an associated value"))),
        }
    }

    fn get_dict(&self, tag: &Tag) -> Result<&BTreeMap<Id, Value>, LocalError> {
        self.mappings
            .get(tag)
            .ok_or_else(|| LocalError::new(format!("Array {tag} not found in storage")))
    }

    fn get_dict_as_value(&self, tag: &Tag) -> Result<Value, LocalError> {
        let dict = self.get_dict(tag)?.clone();
        Ok(Value::new(dict))
    }

    fn get_elem(&self, tag: &Tag, id: &Id) -> Result<Value, LocalError> {
        Ok(self
            .get_dict(tag)?
            .get(id)
            .ok_or_else(|| LocalError::new(format!("{tag}[{id:?}] not found in storage")))?
            .clone())
    }

    fn set_elem(&mut self, tag: &Tag, id: &Id, value: Value) -> Result<(), LocalError> {
        let mapping = self.mappings.entry(tag.clone()).or_default();
        match mapping.insert(id.clone(), value) {
            None => Ok(()),
            Some(_) => Err(LocalError::new(format!(
                "{tag}[{id:?}] already has an associated value"
            ))),
        }
    }
}

#[derive(Debug)]
enum ComputeFunction<SP: SessionParameters, P: Protocol<SP>> {
    Scalar {
        function: WrappedScalarFunction<SP, P>,
    },
    Array {
        function: WrappedArrayFunction<SP, P>,
        id: SP::Verifier,
    },
}

#[derive(Debug)]
pub struct ComputeTask<SP: SessionParameters, P: Protocol<SP>> {
    store_in: Tag,
    function: ComputeFunction<SP, P>,
    args: Args<SP>,
    shared_data: Arc<P::SharedData>,
}

impl<SP: SessionParameters, P: Protocol<SP>> ComputeTask<SP, P> {
    pub fn compute(self) -> Result<TaskResult<SP::Verifier>, LocalError> {
        match self.function {
            ComputeFunction::Scalar { function } => {
                let result = match function.call(&self.shared_data, self.args) {
                    Ok(result) => result,
                    Err(ComputeError::Local(error)) => return Err(error),
                    Err(ComputeError::Data) => todo!(),
                };
                Ok(TaskResult(TaskResultEnum::Compute {
                    store_in: self.store_in.clone(),
                    result,
                }))
            }
            ComputeFunction::Array { function, id } => {
                let result = match function.call(&id, &self.shared_data, self.args) {
                    Ok(result) => result,
                    Err(ComputeError::Local(error)) => return Err(error),
                    Err(ComputeError::Data) => todo!(),
                };
                Ok(TaskResult(TaskResultEnum::ComputeArray {
                    store_in: self.store_in.clone(),
                    id,
                    result,
                }))
            }
        }
    }
}

#[derive(Debug)]
enum ComputeWithRngFunction<SP: SessionParameters, P: Protocol<SP>> {
    Scalar {
        function: WrappedScalarFunctionPrivate<SP, P>,
    },
    Array {
        function: WrappedArrayFunctionPrivate<SP, P>,
        id: SP::Verifier,
    },
}

#[derive(Debug)]
pub struct ComputeWithRngTask<SP: SessionParameters, P: Protocol<SP>> {
    store_in: Tag,
    function: ComputeWithRngFunction<SP, P>,
    args: Args<SP>,
    shared_data: Arc<P::SharedData>,
}

impl<SP: SessionParameters, P: Protocol<SP>> ComputeWithRngTask<SP, P> {
    pub fn compute(self, rng: &mut impl CryptoRngCore) -> Result<TaskResult<SP::Verifier>, LocalError> {
        match self.function {
            ComputeWithRngFunction::Scalar { function } => {
                let result = match function.call(rng, &self.shared_data, self.args) {
                    Ok(result) => result,
                    Err(ComputeError::Local(error)) => return Err(error),
                    Err(ComputeError::Data) => todo!(),
                };
                Ok(TaskResult(TaskResultEnum::Compute {
                    store_in: self.store_in.clone(),
                    result,
                }))
            }
            ComputeWithRngFunction::Array { function, id } => {
                let result = match function.call(rng, &id, &self.shared_data, self.args) {
                    Ok(result) => result,
                    Err(ComputeError::Local(error)) => return Err(error),
                    Err(ComputeError::Data) => todo!(),
                };
                Ok(TaskResult(TaskResultEnum::ComputeArray {
                    store_in: self.store_in.clone(),
                    id,
                    result,
                }))
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
pub enum Task<SP: SessionParameters, P: Protocol<SP>> {
    Send(SendTask<SP>),
    Compute(ComputeTask<SP, P>),
    ComputeWithRng(ComputeWithRngTask<SP, P>),
    Finalize(FinalizeTask),
}

#[derive(Debug)]
pub struct TaskResult<Id>(TaskResultEnum<Id>);

#[derive(Debug)]
enum TaskResultEnum<Id> {
    Send { store_in: Tag, destination: Id },
    Compute { store_in: Tag, result: Value },
    ComputeArray { store_in: Tag, id: Id, result: Value },
}

#[derive(Debug)]
pub struct Session<SP: SessionParameters, P: Protocol<SP>> {
    signer: Arc<SP::Signer>,
    shared_data: Arc<P::SharedData>,
    ruleset: Ruleset<SP, P>,
    storage: Storage<SP::Verifier>,
}

impl<SP, P> Session<SP, P>
where
    SP: SessionParameters,
    P: Protocol<SP>,
{
    pub fn new(signer: SP::Signer, shared_data: P::SharedData) -> Result<Self, LocalError> {
        let output_node = P::build(&signer.verifying_key(), &shared_data)?;
        let ruleset = Ruleset::new(output_node)?;
        let storage = Storage::new();
        let signer = Arc::new(signer);
        Ok(Self {
            signer,
            ruleset,
            storage,
            shared_data: Arc::new(shared_data),
        })
    }

    pub fn id(&self) -> SP::Verifier {
        self.signer.verifying_key()
    }

    pub fn make_task(&mut self) -> Result<Option<Task<SP, P>>, LocalError> {
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
                        .map(|tag: &Tag| self.storage.get(tag).map(|value| (tag.clone(), value)))
                        .collect::<Result<BTreeMap<_, _>, LocalError>>()?;
                    let args = Args::new(&self.signer, &self.id(), arg_values)?;
                    match function {
                        ScalarFunction::Public(function) => {
                            return Ok(Some(Task::Compute(ComputeTask {
                                store_in,
                                function: ComputeFunction::Scalar { function },
                                args,
                                shared_data: self.shared_data.clone(),
                            })));
                        }
                        ScalarFunction::Private(function) => {
                            return Ok(Some(Task::ComputeWithRng(ComputeWithRngTask {
                                store_in,
                                function: ComputeWithRngFunction::Scalar { function },
                                args,
                                shared_data: self.shared_data.clone(),
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
                        .map(|arg: &Arg| match arg {
                            Arg::Scalar(tag) => self.storage.get(tag).map(|value| (tag.clone(), value)),
                            Arg::ArrayElem(tag) => self.storage.get_elem(tag, &index).map(|value| (tag.clone(), value)),
                        })
                        .collect::<Result<BTreeMap<_, _>, LocalError>>()?;
                    let args = Args::new(&self.signer, &self.id(), arg_values)?;
                    match function {
                        ArrayFunction::Public(function) => {
                            return Ok(Some(Task::Compute(ComputeTask {
                                store_in,
                                function: ComputeFunction::Array { function, id: index },
                                args,
                                shared_data: self.shared_data.clone(),
                            })));
                        }
                        ArrayFunction::Private(function) => {
                            return Ok(Some(Task::ComputeWithRng(ComputeWithRngTask {
                                store_in,
                                function: ComputeWithRngFunction::Array { function, id: index },
                                args,
                                shared_data: self.shared_data.clone(),
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

    pub fn add_message(&mut self, message: Message<SP>) -> Result<(), LocalError> {
        for value in message.values() {
            match value.verify() {
                Ok(()) => {}
                Err(VerificationError::Local(error)) => return Err(error),
                Err(VerificationError::SignatureMismatch) => todo!(),
            }
            let source = value.source().clone();
            let tag = Tag::received(value.metadata().name());
            self.storage
                .set_elem(&tag, &source, Value::new(value.serialized_value()))?;
            self.ruleset.update_with_array_element_ready(&tag, &source);
        }
        Ok(())
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
        }
        Ok(())
    }
}
