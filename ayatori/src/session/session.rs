use alloc::{collections::BTreeMap, sync::Arc, vec};
use core::fmt::Debug;

use signature::{Keypair, rand_core::CryptoRngCore};

use super::{
    message::{Message, SignedValue},
    ruleset::{Action, Arg, Ruleset},
};
use crate::protocol::{
    Args, ArrayFunction, Erasable, PartyId, Protocol, ScalarFunction, SessionParameters, Tag, Value,
    WrappedArrayFunction, WrappedArrayFunctionPrivate, WrappedFunction, WrappedFunctionPrivate,
};

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

    fn get(&self, tag: &Tag) -> Value {
        self.scalars.get(tag).unwrap().clone()
    }

    fn set(&mut self, tag: &Tag, value: Value) {
        self.scalars.insert(tag.clone(), value);
    }

    fn get_dict(&self, tag: &Tag) -> Value {
        let dict = self.mappings.get(tag).unwrap().clone();
        Value::new(dict)
    }

    fn get_elem(&self, tag: &Tag, id: &Id) -> Value {
        self.mappings.get(tag).unwrap().get(id).unwrap().clone()
    }

    fn set_elem(&mut self, tag: &Tag, id: &Id, value: Value) {
        if self.mappings.contains_key(tag) {
            self.mappings.get_mut(tag).unwrap().insert(id.clone(), value);
        } else {
            self.mappings.insert(tag.clone(), BTreeMap::from([(id.clone(), value)]));
        }
    }
}

enum ComputeFunction<SP: SessionParameters, P: Protocol<SP>> {
    Scalar {
        function: WrappedFunction<SP, P>,
    },
    Array {
        function: WrappedArrayFunction<SP, P>,
        id: SP::Verifier,
    },
}

pub struct ComputeTask<SP: SessionParameters, P: Protocol<SP>> {
    store_in: Tag,
    function: ComputeFunction<SP, P>,
    args: Args<SP>,
    shared_data: Arc<P::SharedData>,
}

impl<SP: SessionParameters, P: Protocol<SP>> ComputeTask<SP, P> {
    pub fn compute(self) -> TaskResult<SP::Verifier> {
        match self.function {
            ComputeFunction::Scalar { function } => {
                let result = function.call(&self.shared_data, self.args);
                TaskResult(TaskResultEnum::Compute {
                    store_in: self.store_in.clone(),
                    result,
                })
            }
            ComputeFunction::Array { function, id } => {
                let result = function.call(&id, &self.shared_data, self.args);
                TaskResult(TaskResultEnum::ComputeArray {
                    store_in: self.store_in.clone(),
                    id,
                    result,
                })
            }
        }
    }
}

enum ComputeWithRngFunction<SP: SessionParameters, P: Protocol<SP>> {
    Scalar {
        function: WrappedFunctionPrivate<SP, P>,
    },
    Array {
        function: WrappedArrayFunctionPrivate<SP, P>,
        id: SP::Verifier,
    },
}

pub struct ComputeWithRngTask<SP: SessionParameters, P: Protocol<SP>> {
    store_in: Tag,
    function: ComputeWithRngFunction<SP, P>,
    args: Args<SP>,
    shared_data: Arc<P::SharedData>,
}

impl<SP: SessionParameters, P: Protocol<SP>> ComputeWithRngTask<SP, P> {
    pub fn compute(self, rng: &mut impl CryptoRngCore) -> TaskResult<SP::Verifier> {
        match self.function {
            ComputeWithRngFunction::Scalar { function } => {
                let result = function.call(rng, &self.shared_data, self.args);
                TaskResult(TaskResultEnum::Compute {
                    store_in: self.store_in.clone(),
                    result,
                })
            }
            ComputeWithRngFunction::Array { function, id } => {
                let result = function.call(rng, &id, &self.shared_data, self.args);
                TaskResult(TaskResultEnum::ComputeArray {
                    store_in: self.store_in.clone(),
                    id,
                    result,
                })
            }
        }
    }
}

pub struct SendTask<SP: SessionParameters> {
    store_in: Tag,
    destination: SP::Verifier,
    signed_value: Value,
}

impl<SP: SessionParameters> SendTask<SP> {
    pub fn compute(self) -> (Message<SP>, TaskResult<SP::Verifier>) {
        let signed_value = self.signed_value.downcast::<SignedValue<SP>>();
        let signed_values = vec![signed_value];
        let message = Message::new(self.destination.clone(), signed_values);
        let result = TaskResult(TaskResultEnum::Send {
            store_in: self.store_in.clone(),
            destination: self.destination.clone(),
        });
        (message, result)
    }
}

pub struct FinalizeTask {
    outcome: Value,
}

impl FinalizeTask {
    pub fn value<T: Clone + Erasable>(self) -> T {
        self.outcome.downcast::<T>()
    }
}

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
    pub fn new(signer: SP::Signer, shared_data: P::SharedData) -> Self {
        let output_node = P::build(&signer.verifying_key(), &shared_data);
        let ruleset = Ruleset::new(output_node);
        let storage = Storage::new();
        let signer = Arc::new(signer);
        Self {
            signer,
            ruleset,
            storage,
            shared_data: Arc::new(shared_data),
        }
    }

    pub fn id(&self) -> SP::Verifier {
        self.signer.verifying_key()
    }

    pub fn make_task(&mut self) -> Option<Task<SP, P>> {
        if self.storage.contains(self.ruleset.output_tag()) {
            return Some(Task::Finalize(FinalizeTask {
                outcome: self.storage.get(self.ruleset.output_tag()),
            }));
        }

        if self.ruleset.is_empty() {
            panic!("No rules to apply, and the output value has not been set");
        }

        loop {
            let action = match self.ruleset.pop_action() {
                Some(action) => action,
                None => break,
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
                    };

                    return Some(Task::Send(SendTask {
                        store_in,
                        destination: destination.clone(),
                        signed_value,
                    }));
                }
                Action::ComputeScalar {
                    store_in,
                    function,
                    args,
                } => {
                    let arg_values = args
                        .iter()
                        .map(|arg: &Tag| (arg.clone(), self.storage.get(arg)))
                        .collect::<BTreeMap<_, _>>();
                    let args = Args::new(&self.signer, &self.id(), arg_values);
                    match function {
                        ScalarFunction::Public(function) => {
                            return Some(Task::Compute(ComputeTask {
                                store_in,
                                function: ComputeFunction::Scalar { function },
                                args,
                                shared_data: self.shared_data.clone(),
                            }));
                        }
                        ScalarFunction::Private(function) => {
                            return Some(Task::ComputeWithRng(ComputeWithRngTask {
                                store_in,
                                function: ComputeWithRngFunction::Scalar { function },
                                args,
                                shared_data: self.shared_data.clone(),
                            }));
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
                            Arg::Scalar(tag) => (tag.clone(), self.storage.get(tag)),
                            Arg::ArrayElem(tag) => (tag.clone(), self.storage.get_elem(tag, &index)),
                        })
                        .collect::<BTreeMap<_, _>>();
                    let args = Args::new(&self.signer, &self.id(), arg_values);
                    match function {
                        ArrayFunction::Public(function) => {
                            return Some(Task::Compute(ComputeTask {
                                store_in,
                                function: ComputeFunction::Array { function, id: index },
                                args,
                                shared_data: self.shared_data.clone(),
                            }));
                        }
                        ArrayFunction::Private(function) => {
                            return Some(Task::ComputeWithRng(ComputeWithRngTask {
                                store_in,
                                function: ComputeWithRngFunction::Array { function, id: index },
                                args,
                                shared_data: self.shared_data.clone(),
                            }));
                        }
                    }
                }
                Action::Collect { store_in, values } => {
                    self.storage.set(&store_in, self.storage.get_dict(&values));
                    self.ruleset.update_with_value_ready(&store_in);
                }
            }
        }

        None
    }

    pub fn add_message(&mut self, message: Message<SP>) {
        for value in message.values() {
            value.verify().unwrap();
            let source = value.source().clone();
            let tag = Tag::received(value.metadata().name());
            self.storage
                .set_elem(&tag, &source, Value::new(value.serialized_value()));
            self.ruleset.update_with_array_element_ready(&tag, &source);
        }
    }

    pub fn add_result(&mut self, result: TaskResult<SP::Verifier>) {
        match result.0 {
            TaskResultEnum::Send { store_in, destination } => {
                self.storage.set_elem(&store_in, &destination, Value::new(()));
                self.ruleset.update_with_array_element_ready(&store_in, &destination);
            }
            TaskResultEnum::Compute { store_in, result } => {
                self.storage.set(&store_in, result);
                self.ruleset.update_with_value_ready(&store_in);
            }
            TaskResultEnum::ComputeArray { store_in, id, result } => {
                self.storage.set_elem(&store_in, &id, result);
                self.ruleset.update_with_array_element_ready(&store_in, &id);
            }
        }
    }
}
