use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    sync::Arc,
};

use itertools::Itertools;

use super::{
    constructors::scalar_argument,
    node::Node,
    tag::FullName,
    traits::SessionParameters,
    value::{Erasable, Value},
};
use crate::{
    error::LocalError,
    session::{SessionData, SessionId},
};

#[derive(Debug)]
pub struct Args<SP: SessionParameters> {
    // TODO: this is only needed for serialization/deserialization closures.
    // Seems like a crutch. Can we somehow avoid it?
    store_in_name: FullName,
    session_data: Arc<SessionData<SP>>,
    my_id: SP::Verifier,
    values: BTreeMap<String, Value>,
}

impl<SP: SessionParameters> Args<SP> {
    pub(crate) fn new(
        store_in_name: &FullName,
        session_data: &Arc<SessionData<SP>>,
        my_id: &SP::Verifier,
        values: BTreeMap<String, Value>,
    ) -> Result<Self, LocalError> {
        Ok(Self {
            store_in_name: store_in_name.clone(),
            session_data: session_data.clone(),
            my_id: my_id.clone(),
            values,
        })
    }

    pub(crate) fn store_in_name(&self) -> &FullName {
        &self.store_in_name
    }

    pub(crate) fn session_data(&self) -> &SessionData<SP> {
        &self.session_data
    }

    pub(crate) fn signer(&self) -> &SP::Signer {
        &self.session_data.signer
    }

    pub fn my_id(&self) -> &SP::Verifier {
        &self.my_id
    }

    pub fn session_id(&self) -> &SessionId<SP> {
        &self.session_data.id
    }

    pub(crate) fn get_value(&self, name: &str) -> Result<&Value, LocalError> {
        self.values.get(name).ok_or_else(|| {
            LocalError::new(format!(
                "Value {name} is not present in the Args (have: {})",
                self.values.keys().join(", ")
            ))
        })
    }

    pub fn get<T: Erasable>(&self, name: &str) -> Result<&T, LocalError> {
        self.get_value(name)?.downcast_ref::<T>()
    }

    pub fn get_map<T: Clone + Erasable>(&self, name: &str) -> Result<BTreeMap<&SP::Verifier, &T>, LocalError> {
        let value_map = self.get::<BTreeMap<SP::Verifier, Value>>(name)?;
        value_map
            .iter()
            .map(|(id, value)| value.downcast_ref::<T>().map(|value_ref| (id, value_ref)))
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct PrivateInputs(BTreeMap<String, Value>);

impl PrivateInputs {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn input<T: Erasable>(self, name: &str, value: T) -> Self {
        let mut args = self.0;
        args.insert(name.to_string(), Value::new(value));
        Self(args)
    }

    pub fn names(&self) -> BTreeSet<String> {
        self.0.keys().cloned().collect()
    }

    pub(crate) fn into_inner(self) -> BTreeMap<String, Value> {
        self.0
    }
}

#[derive(Debug, Default)]
pub struct PublicInputs(BTreeMap<String, Value>);

impl PublicInputs {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn input<T: Erasable>(self, name: &str, value: T) -> Self {
        let mut args = self.0;
        args.insert(name.to_string(), Value::new(value));
        Self(args)
    }

    pub(crate) fn into_inner(self) -> BTreeMap<String, Value> {
        self.0
    }
}

#[derive(Debug, Default)]
pub struct ArgNodes<SP: SessionParameters>(BTreeMap<String, Node<SP>>);

impl<SP: SessionParameters> ArgNodes<SP> {
    pub(crate) fn new(signature: &ProtocolSignature) -> Self {
        Self(
            signature
                .0
                .iter()
                .map(|name| (name.clone(), scalar_argument(name)))
                .collect(),
        )
    }

    pub fn get(&self, name: &str) -> Result<&Node<SP>, LocalError> {
        self.0
            .get(name)
            .ok_or_else(|| LocalError::new(format!("Argument {name} was not found")))
    }
}

#[derive(Debug, Default)]
pub struct ProtocolArgs<SP: SessionParameters>(BTreeMap<String, Node<SP>>);

impl<SP: SessionParameters> ProtocolArgs<SP> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn input(self, name: &str, value: &Node<SP>) -> Self {
        let mut args = self.0;
        args.insert(name.to_string(), value.get_strong_ref());
        Self(args)
    }

    pub fn nodes(&self) -> &BTreeMap<String, Node<SP>> {
        &self.0
    }

    pub fn get(&self, name: &str) -> Result<&Node<SP>, LocalError> {
        self.0
            .get(name)
            .ok_or_else(|| LocalError::new(format!("Argument {name} was not found")))
    }
}

#[derive(Debug, Default)]
pub struct ProtocolSignature(BTreeSet<String>);

impl ProtocolSignature {
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    pub fn input(self, name: &str) -> Self {
        let mut args = self.0;
        args.insert(name.to_string());
        Self(args)
    }

    pub(crate) fn bind<SP: SessionParameters>(
        &self,
        args: ProtocolArgs<SP>,
    ) -> Result<BoundProtocolArgs<SP>, LocalError> {
        if self.0 != args.0.keys().cloned().collect::<BTreeSet<_>>() {
            return Err(LocalError::new("Argument mismatch when binding"));
        }

        Ok(BoundProtocolArgs(args.0))
    }
}

pub(crate) struct BoundProtocolArgs<SP: SessionParameters>(BTreeMap<String, Node<SP>>);

impl<SP: SessionParameters> BoundProtocolArgs<SP> {
    pub fn get(&self, name: &str) -> Result<&Node<SP>, LocalError> {
        self.0
            .get(name)
            .ok_or_else(|| LocalError::new(format!("Bound argument {name} was not found")))
    }
}
