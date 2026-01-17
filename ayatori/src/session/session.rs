use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::any::Any;
use rand_core::CryptoRng;

use super::ruleset::{Action, Arg, Ruleset};
use crate::protocol::{
    Args, PartyId, Protocol, Tag, Value, WrappedArrayFunction, WrappedFunction, WrappedFunctionPrivate,
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

enum ComputeFunction<Id: PartyId, P: Protocol<Id>> {
    Scalar {
        function: WrappedFunction<Id, P>,
    },
    Array {
        function: WrappedArrayFunction<Id, P>,
        id: Id,
    },
}

pub struct ComputeTask<Id: PartyId, P: Protocol<Id>> {
    store_in: Tag,
    function: ComputeFunction<Id, P>,
    args: Args,
    shared_data: Arc<P::SharedData>,
}

impl<Id: PartyId, P: Protocol<Id>> ComputeTask<Id, P> {
    pub fn compute(self) -> TaskResult<Id> {
        match self.function {
            ComputeFunction::Scalar { function } => {
                let result = function.call(&self.shared_data, self.args);
                TaskResult::Compute {
                    store_in: self.store_in.clone(),
                    result,
                }
            }
            ComputeFunction::Array { function, id } => {
                let result = function.call(&id, &self.shared_data, self.args);
                TaskResult::ComputeArray {
                    store_in: self.store_in.clone(),
                    id,
                    result,
                }
            }
        }
    }
}

pub struct ComputeWithRngTask<Id: PartyId, P: Protocol<Id>> {
    store_in: Tag,
    function: WrappedFunctionPrivate<Id, P>,
    args: Args,
    shared_data: Arc<P::SharedData>,
}

impl<Id: PartyId, P: Protocol<Id>> ComputeWithRngTask<Id, P> {
    pub fn compute(self, rng: &mut impl CryptoRng) -> TaskResult<Id> {
        let result = self.function.call(rng, &self.shared_data, self.args);
        TaskResult::Compute {
            store_in: self.store_in.clone(),
            result,
        }
    }
}

pub struct SendTask<Id> {
    store_in: Tag,
    send_as: Tag,
    destination: Id,
    data: Value,
}

impl<Id: PartyId> SendTask<Id> {
    pub fn destination(&self) -> &Id {
        &self.destination
    }
    pub fn data(self) -> Value {
        self.data
    }
    pub fn tag(&self) -> &Tag {
        &self.send_as
    }
    pub fn result(&self) -> TaskResult<Id> {
        TaskResult::Send {
            store_in: self.store_in.clone(),
            destination: self.destination.clone(),
        }
    }
}

pub struct FinalizeTask {
    outcome: Value,
}

impl FinalizeTask {
    pub fn value<T: Clone + Any + Send + Sync>(self) -> T {
        self.outcome.downcast::<T>()
    }
}

pub enum Task<Id: PartyId, P: Protocol<Id>> {
    Send(SendTask<Id>),
    Compute(ComputeTask<Id, P>),
    ComputeWithRng(ComputeWithRngTask<Id, P>),
    Finalize(FinalizeTask),
}

#[derive(Debug)]
pub enum TaskResult<Id> {
    Send { store_in: Tag, destination: Id },
    Compute { store_in: Tag, result: Value },
    ComputeArray { store_in: Tag, id: Id, result: Value },
}

pub struct Session<Id: PartyId, P: Protocol<Id>> {
    my_id: Id,
    shared_data: Arc<P::SharedData>,
    ruleset: Ruleset<Id, P>,
    storage: Storage<Id>,
}

impl<Id: PartyId, P: Protocol<Id>> Session<Id, P> {
    pub fn new(my_id: &Id, shared_data: P::SharedData) -> Self {
        let output_node = P::build(my_id, &shared_data);
        let ruleset = Ruleset::new(output_node);

        let storage = Storage::new();
        Self {
            my_id: my_id.clone(),
            ruleset,
            storage,
            shared_data: Arc::new(shared_data),
        }
    }

    pub fn id(&self) -> &Id {
        &self.my_id
    }

    pub fn make_task(&mut self) -> Option<Task<Id, P>> {
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
                    send_as,
                    to_send,
                    destination,
                } => {
                    return Some(Task::Send(SendTask {
                        store_in,
                        send_as,
                        destination,
                        data: self.storage.get(&to_send),
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
                    let args = Args::new(arg_values);
                    return Some(Task::Compute(ComputeTask {
                        store_in,
                        function: ComputeFunction::Scalar { function },
                        args,
                        shared_data: self.shared_data.clone(),
                    }));
                }
                Action::ComputeScalarPrivate {
                    store_in,
                    function,
                    args,
                } => {
                    let arg_values = args
                        .iter()
                        .map(|arg: &Tag| (arg.clone(), self.storage.get(arg)))
                        .collect::<BTreeMap<_, _>>();
                    let args = Args::new(arg_values);
                    return Some(Task::ComputeWithRng(ComputeWithRngTask {
                        store_in,
                        function,
                        args,
                        shared_data: self.shared_data.clone(),
                    }));
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
                    let args = Args::new(arg_values);
                    return Some(Task::Compute(ComputeTask {
                        store_in,
                        function: ComputeFunction::Array { function, id: index },
                        args,
                        shared_data: self.shared_data.clone(),
                    }));
                }
                Action::Collect { store_in, values } => {
                    self.storage.set(&store_in, self.storage.get_dict(&values));
                    self.ruleset.update_with_value_ready(&store_in);
                }
            }
        }

        None
    }

    pub fn add_message(&mut self, source: &Id, tag: &Tag, message: Value) {
        self.storage.set_elem(tag, source, message);
        self.ruleset.update_with_array_element_ready(tag, source);
    }

    pub fn add_result(&mut self, result: TaskResult<Id>) {
        match result {
            TaskResult::Send { store_in, destination } => {
                self.storage.set_elem(&store_in, &destination, Value::new(true));
                self.ruleset.update_with_array_element_ready(&store_in, &destination);
            }
            TaskResult::Compute { store_in, result } => {
                self.storage.set(&store_in, result);
                self.ruleset.update_with_value_ready(&store_in);
            }
            TaskResult::ComputeArray { store_in, id, result } => {
                self.storage.set_elem(&store_in, &id, result);
                self.ruleset.update_with_array_element_ready(&store_in, &id);
            }
        }
    }
}
