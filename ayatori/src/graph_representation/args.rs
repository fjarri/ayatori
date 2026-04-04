use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
};

use super::{constructors::scalar_argument, node::Node};
use crate::{
    entities::{Erasable, RuntimeError, Value},
    traits::SessionParameters,
};

#[derive(Debug, Clone)]
pub struct PartyBuildData<SP: SessionParameters> {
    id: SP::Verifier,
}

impl<SP: SessionParameters> PartyBuildData<SP> {
    // Intentionally not creatable by the user since we use it to propagate the party ID to subprotocols,
    // and we don't want it to be possible to build a subprotocol with a different ID.
    pub(crate) fn new(id: &SP::Verifier) -> Self {
        Self { id: id.clone() }
    }

    pub fn id(&self) -> &SP::Verifier {
        &self.id
    }
}

#[derive(Debug, Default)]
pub struct PrivateInputs(BTreeMap<String, Value>);

impl PrivateInputs {
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    #[must_use]
    pub fn input<T: Erasable>(self, name: &str, value: T) -> Self {
        let mut args = self.0;
        args.insert(name.to_string(), Value::new(value));
        Self(args)
    }

    #[must_use]
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
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    #[must_use]
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

    pub fn get(&self, name: &str) -> Result<&Node<SP>, RuntimeError> {
        self.0
            .get(name)
            .ok_or_else(|| RuntimeError::new(format!("Argument {name} was not found")))
    }
}

#[derive(Debug, Default)]
pub struct ProtocolArgs<SP: SessionParameters>(BTreeMap<String, Node<SP>>);

impl<SP: SessionParameters> ProtocolArgs<SP> {
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    #[must_use]
    pub fn input(self, name: &str, value: &Node<SP>) -> Self {
        let mut args = self.0;
        args.insert(name.to_string(), value.get_strong_ref());
        Self(args)
    }

    #[must_use]
    pub fn nodes(&self) -> &BTreeMap<String, Node<SP>> {
        &self.0
    }

    pub fn get(&self, name: &str) -> Result<&Node<SP>, RuntimeError> {
        self.0
            .get(name)
            .ok_or_else(|| RuntimeError::new(format!("Argument {name} was not found")))
    }
}

#[derive(Debug, Default)]
pub struct ProtocolSignature(BTreeSet<String>);

impl ProtocolSignature {
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    #[must_use]
    pub fn input(self, name: &str) -> Self {
        let mut args = self.0;
        args.insert(name.to_string());
        Self(args)
    }

    pub(crate) fn bind<SP: SessionParameters>(
        &self,
        args: ProtocolArgs<SP>,
    ) -> Result<BoundProtocolArgs<SP>, RuntimeError> {
        if self.0 != args.0.keys().cloned().collect::<BTreeSet<_>>() {
            return Err(RuntimeError::new("Argument mismatch when binding"));
        }

        Ok(BoundProtocolArgs(args.0))
    }
}

pub(crate) struct BoundProtocolArgs<SP: SessionParameters>(BTreeMap<String, Node<SP>>);

impl<SP: SessionParameters> BoundProtocolArgs<SP> {
    pub fn get(&self, name: &str) -> Result<&Node<SP>, RuntimeError> {
        self.0
            .get(name)
            .ok_or_else(|| RuntimeError::new(format!("Bound argument {name} was not found")))
    }
}
