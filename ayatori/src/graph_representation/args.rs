use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
};

use super::{constructors::scalar_argument, node::Node};
use crate::{
    entities::{Erasable, Value},
    errors::LocalError,
    traits::SessionParameters,
};

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
