use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
};

use super::{
    any_node::AnyNode,
    constructors::scalar_argument,
    typed_nodes::{Node, ScalarArgument},
};
use crate::{
    entities::{Erasable, RuntimeError, Value},
    traits::SessionParameters,
};

#[cfg(doc)]
use crate::protocol_author_api::{ComposableProtocol, ExecutableProtocol, call_protocol};

/// Party-specific data available during the build stage of the protocol.
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

    /// The ID of the party for which the protocol is being built.
    pub fn id(&self) -> &SP::Verifier {
        &self.id
    }
}

/// Private party-specific inputs to the protocol (see [`ExecutableProtocol::make_private_inputs`]).
///
/// These inputs cannot be used to verify evidence of malicious behavior,
/// so a failure of a node that has these inputs as its leaves is unprovable.
#[derive(Debug, Default)]
pub struct PrivateInputs(BTreeMap<String, Value>);

impl PrivateInputs {
    /// Creates a new inputs structure.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Adds an input to the list.
    ///
    /// The name should be one of those mentioned in [`ComposableProtocol::signature`].
    #[must_use]
    pub fn input<T: Erasable>(self, name: &str, value: T) -> Self {
        let mut args = self.0;
        args.insert(name.to_string(), Value::new(value));
        Self(args)
    }

    #[must_use]
    pub(crate) fn names(&self) -> BTreeSet<String> {
        self.0.keys().cloned().collect()
    }

    pub(crate) fn into_inner(self) -> BTreeMap<String, Value> {
        self.0
    }
}

/// Shared public inputs to the protocol (see [`ExecutableProtocol::make_public_inputs`]).
#[derive(Debug, Default)]
pub struct PublicInputs(BTreeMap<String, Value>);

impl PublicInputs {
    /// Creates a new inputs structure.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Adds an input to the list.
    ///
    /// The name should be one of those mentioned in [`ComposableProtocol::signature`].
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

/// A structure containing [`ScalarArgument`] nodes corresponding to the inputs
/// declared in [`PrivateInputs`] and [`PublicInputs`].
#[derive(Debug, Default)]
pub struct ArgNodes<SP: SessionParameters>(BTreeMap<String, Node<ScalarArgument<SP>>>);

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

    /// Returns the node corresponding to the input named `name`.
    pub fn get(&self, name: &str) -> Result<&Node<ScalarArgument<SP>>, RuntimeError> {
        self.0
            .get(name)
            .ok_or_else(|| RuntimeError::new(format!("Argument {name} was not found")))
    }
}

/// A structure used to define inputs to a sub-protocol (see [`call_protocol`]).
#[derive(Debug, Default)]
pub struct ProtocolArgs<SP: SessionParameters>(BTreeMap<String, AnyNode<SP>>);

impl<SP: SessionParameters> ProtocolArgs<SP> {
    /// Creates a new inputs structure.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Adds an input to the list.
    ///
    /// The name should be one of those mentioned in [`ComposableProtocol::signature`].
    #[must_use]
    pub fn input(self, name: &str, value: impl Into<AnyNode<SP>>) -> Self {
        let mut args = self.0;
        args.insert(name.to_string(), value.into());
        Self(args)
    }
}

/// A structure used to define the protocol signature in [`ComposableProtocol::signature`].
#[derive(Debug, Default)]
pub struct ProtocolSignature(BTreeSet<String>);

impl ProtocolSignature {
    /// Creates an empty structure.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Adds an input to the list.
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

pub(crate) struct BoundProtocolArgs<SP: SessionParameters>(BTreeMap<String, AnyNode<SP>>);

impl<SP: SessionParameters> BoundProtocolArgs<SP> {
    pub fn get(&self, name: &str) -> Result<&AnyNode<SP>, RuntimeError> {
        self.0
            .get(name)
            .ok_or_else(|| RuntimeError::new(format!("Bound argument {name} was not found")))
    }
}
