use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
};

use itertools::Itertools;

use super::{
    errors::RuntimeError,
    message::VerifiedValue,
    session_id::SessionId,
    tag::FullName,
    value::{Erasable, SerdeAdapter, Value},
};
use crate::{error::TraceableResult, traits::SessionParameters};

#[cfg(doc)]
use crate::protocol_author_api::{
    Collect, ComposableProtocol, ComputeMapping, ComputeScalar, MergeScalars, SerializeAndSign, compute_forked_scalar,
    compute_forked_scalar_with_rng,
};

/// Arguments for the function in [`SerializeAndSign`] node.
#[derive_where::derive_where(Debug)]
pub struct SerializeArgs<SP: SessionParameters> {
    signer: Arc<SP::Signer>,
    session_id: SessionId<SP>,
    message_name: FullName,
    serde_adapter: SerdeAdapter<SP::WireFormat>,
    value: Value,
}

impl<SP: SessionParameters> SerializeArgs<SP> {
    pub(crate) fn new(
        signer: &Arc<SP::Signer>,
        session_id: &SessionId<SP>,
        message_name: FullName,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        value: Value,
    ) -> Self {
        Self {
            signer: signer.clone(),
            session_id: session_id.clone(),
            message_name,
            serde_adapter,
            value,
        }
    }

    /// Returns the session signer.
    pub fn signer(&self) -> &SP::Signer {
        &self.signer
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> &SessionId<SP> {
        &self.session_id
    }

    /// Returns the name of the protocol message that will contain the serialized value.
    pub fn message_name(&self) -> &FullName {
        &self.message_name
    }

    /// Returns the `serde` adapter that needs to be used to serialize the value.
    pub fn serde_adapter(&self) -> &SerdeAdapter<SP::WireFormat> {
        &self.serde_adapter
    }

    pub(crate) fn value(&self) -> &Value {
        &self.value
    }
}

#[derive_where::derive_where(Debug)]
pub struct DeserializeArgs<SP: SessionParameters> {
    serde_adapter: SerdeAdapter<SP::WireFormat>,
    value: Value,
    expected_senders: BTreeSet<SP::Verifier>,
}

impl<SP: SessionParameters> DeserializeArgs<SP> {
    pub(crate) fn new(
        expected_senders: &BTreeSet<SP::Verifier>,
        serde_adapter: SerdeAdapter<SP::WireFormat>,
        value: Value,
    ) -> Self {
        Self {
            serde_adapter,
            value,
            expected_senders: expected_senders.clone(),
        }
    }

    pub fn expected_senders(&self) -> &BTreeSet<SP::Verifier> {
        &self.expected_senders
    }

    pub fn serde_adapter(&self) -> &SerdeAdapter<SP::WireFormat> {
        &self.serde_adapter
    }

    pub(crate) fn verified_value(&self) -> Result<&VerifiedValue<SP>, RuntimeError> {
        self.value
            .downcast_ref::<VerifiedValue<SP>>()
            .or_with_context(|| "Failed to downcast a `VerifiedValue`".into())
    }
}

/// Arguments for the function in a [`ComputeScalar`] or a [`ComputeMapping`] node.
#[derive_where::derive_where(Debug)]
pub struct Args<SP: SessionParameters> {
    session_id: SessionId<SP>,
    my_id: SP::Verifier,
    values: BTreeMap<String, Value>,
}

impl<SP: SessionParameters> Args<SP> {
    pub(crate) fn new(session_id: &SessionId<SP>, my_id: &SP::Verifier, values: BTreeMap<String, Value>) -> Self {
        Self {
            session_id: session_id.clone(),
            my_id: my_id.clone(),
            values,
        }
    }

    /// Returns the ID for the party performing the computation.
    pub fn my_id(&self) -> &SP::Verifier {
        &self.my_id
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> &SessionId<SP> {
        &self.session_id
    }

    pub(crate) fn get_value(&self, name: &str) -> Result<&Value, RuntimeError> {
        self.values.get(name).ok_or_else(|| {
            RuntimeError::new(format!(
                "Value {name} is not present in the Args (have: {})",
                self.values.keys().join(", ")
            ))
        })
    }

    /// Returns the value from the storage slot that was declared as the argument for this computation
    /// during [`ComposableProtocol::build`].
    ///
    /// Fails if `name` was not present in the argument list, or the type of the stored value is not `T`.
    pub fn get<T: Erasable>(&self, name: &str) -> Result<&T, RuntimeError> {
        self.get_value(name)?
            .downcast_ref::<T>()
            .or_with_context(|| format!("Failed to downcast the value `{name}`"))
    }

    /// Returns the value from the storage slot that was declared as the argument for this computation
    /// during [`ComposableProtocol::build`].
    ///
    /// Intended to be used only for storage slots of [`Collect`] nodes.
    /// Fails if `name` was not present in the argument list, or the stored value was not collected
    /// from a mapping of values of type `T`.
    pub fn get_map<T: Clone + Erasable>(&self, name: &str) -> Result<BTreeMap<&SP::Verifier, &T>, RuntimeError> {
        let value_map = self.get::<BTreeMap<SP::Verifier, Value>>(name)?;
        value_map
            .iter()
            .map(|(id, value)| {
                value
                    .downcast_ref::<T>()
                    .map(|value_ref| (id, value_ref))
                    .or_with_context(|| format!("Failed to downcast the element `{id:?}` of the mapping `{name}`"))
            })
            .collect()
    }

    /// Returns the value from the storage slot that was declared as the argument for this computation
    /// during [`ComposableProtocol::build`].
    ///
    /// Intended to be used only for storage slots of [`MergeScalars`] nodes.
    /// Fails if `name` was not present in the argument list, or the stored value was not merged
    /// from values of type `L` and `R`.
    pub fn get_merged<L: Clone + Erasable, R: Clone + Erasable>(
        &self,
        name: &str,
    ) -> Result<OneOrBoth<&L, &R>, RuntimeError> {
        Ok(match self.get::<OneOrBoth<Value, Value>>(name)? {
            OneOrBoth::Left(left) => OneOrBoth::Left(
                left.downcast_ref::<L>()
                    .or_with_context(|| format!("Failed to downcast the left variant of the merged value `{name}`"))?,
            ),
            OneOrBoth::Right(right) => OneOrBoth::Right(
                right
                    .downcast_ref::<R>()
                    .or_with_context(|| format!("Failed to downcast the right variant of the merged value `{name}`"))?,
            ),
            OneOrBoth::Both { left, right } => {
                let left = left
                    .downcast_ref::<L>()
                    .or_with_context(|| format!("Failed to downcast the left variant of the merged value `{name}`"))?;
                let right = right
                    .downcast_ref::<R>()
                    .or_with_context(|| format!("Failed to downcast the right variant of the merged value `{name}`"))?;
                OneOrBoth::Both { left, right }
            }
        })
    }
}

/// A type used as the return value of functions in fork nodes
/// (see [`compute_forked_scalar`] and [`compute_forked_scalar_with_rng`]).
#[derive(Debug)]
pub enum OneOrBoth<L, R> {
    /// Only the first option is returned and stored.
    Left(L),
    /// Only the second option is returned and stored.
    Right(R),
    /// Both options are returned and stored.
    Both {
        /// First option.
        left: L,
        /// Second option.
        right: R,
    },
}
