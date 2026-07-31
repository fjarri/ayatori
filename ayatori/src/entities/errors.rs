use alloc::{format, string::String};
use core::{
    fmt::{Debug, Display},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};

use super::value::SerializedValue;
use crate::{
    traced_error::{Traceable, TraceableResult, TracedError},
    traits::{SessionParameters, WireFormat},
};

/// An error returned when attempting to downcast from a larger union type to a smaller one (or a single type),
/// and the variant of the larger union is not present in the smalle one.
#[derive(Debug, Clone, Copy, displaydoc::Display)]
#[displaydoc("Failed to narrow down a union")]
pub struct UnionCastError;

impl core::error::Error for UnionCastError {}

/// A randomly occuring error that is not a result of a misuse of the API, or malicious actions of other parties.
///
/// Getting this error during a protocol execution means that the protocol can just be restarted
/// with the same participants.
///
/// An example of when this error can occur would be a protocol
/// where every party generates a secret random curve scalar `x_i`, and reveals the curve point `g^{x_i}`.
/// It is possible that by no fault of any party these would add up to the infinity point,
/// in which case this error will be returned.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Spurious error: {0}")]
pub struct SpuriousError(String);

impl SpuriousError {
    /// Creates a new error with the given description.
    pub fn new(description: impl Into<String>) -> Self {
        Self(description.into())
    }
}

impl core::error::Error for SpuriousError {}

/// An error where some check that couldn't be ensured via the type system failed ar runtime.
///
/// This error indicates that there is either a problem with the environment, or there is a bug in the code.
/// The protocol should not be restarted until the problem is fixed.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Runtime error: {0}")]
pub struct RuntimeError(TracedError);

impl RuntimeError {
    /// Creates a new error with the given description.
    #[track_caller]
    pub fn new(description: impl Into<String>) -> Self {
        Self(TracedError::new(description))
    }
}

impl Traceable for RuntimeError {
    #[track_caller]
    fn with_context(self, context: impl Into<String>) -> Self {
        Self(self.0.with_context(context))
    }
}

impl core::error::Error for RuntimeError {}

/// An error during computation that is not attributable to a specific party.
#[derive(displaydoc::Display, Debug, Clone)]
pub enum UnattributableError {
    /// See [`SpuriousError`].
    #[displaydoc("{0}")]
    Spurious(SpuriousError),
    /// See [`RuntimeError`].
    #[displaydoc("{0}")]
    Runtime(RuntimeError),
}

impl From<RuntimeError> for UnattributableError {
    fn from(source: RuntimeError) -> Self {
        Self::Runtime(source)
    }
}

impl From<SpuriousError> for UnattributableError {
    fn from(source: SpuriousError) -> Self {
        Self::Spurious(source)
    }
}

impl UnattributableError {
    /// Returns the [`UnattributableError::Spurious`] variant.
    pub fn spurious(description: impl Into<String>) -> Self {
        Self::Spurious(SpuriousError::new(description))
    }

    /// Returns the [`UnattributableError::Runtime`] variant.
    #[track_caller]
    pub fn runtime(description: impl Into<String>) -> Self {
        Self::Runtime(RuntimeError::new(description))
    }
}

impl core::error::Error for UnattributableError {}

/// An error occuring during a computation that may be attributable to a specific party.
#[derive(displaydoc::Display, Debug, Clone)]
pub enum MaybeAttributableError<E> {
    /// An environment error or a bug. See [`RuntimeError`].
    #[displaydoc("{0}")]
    Runtime(RuntimeError),
    /// The attributable variant. See the documentation for the specific type.
    #[displaydoc("{0}")]
    Attributable(E),
}

impl<E> From<RuntimeError> for MaybeAttributableError<E> {
    fn from(source: RuntimeError) -> Self {
        Self::Runtime(source)
    }
}

/// An error attributable to the party with the element's ID.
#[derive(displaydoc::Display, Debug, Clone, Serialize, Deserialize)]
#[displaydoc("Sender error: {description}")]
pub struct SenderError {
    description: String,
}

impl<E: Debug + Display> core::error::Error for MaybeAttributableError<E> {}

impl SenderError {
    /// Creates a new error with the given description.
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
        }
    }
}

impl From<SenderError> for MaybeAttributableError<SenderError> {
    fn from(source: SenderError) -> Self {
        Self::Attributable(source)
    }
}

impl core::error::Error for SenderError {}

/// Additional data (not calculated in the nodes leading to the error) to be attached to the evidence.
#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
pub struct AssociatedData<SP: SessionParameters> {
    serialized_value: SerializedValue,
    phantom: PhantomData<fn() -> SP>,
}

impl<SP: SessionParameters> AssociatedData<SP> {
    pub(crate) fn new<T: Serialize + for<'de> Deserialize<'de>>(value: T) -> Result<Self, RuntimeError> {
        let serialized_value = SerializedValue::new(SP::WireFormat::serialize(value)?);
        Ok(Self {
            serialized_value,
            phantom: PhantomData,
        })
    }

    /// Returns the typed data that was stored during evidence creation.
    ///
    /// Fails on type mismatch.
    pub fn extract<T: for<'de> Deserialize<'de>>(&self) -> Result<T, RuntimeError> {
        SP::WireFormat::deserialize::<T>(self.serialized_value.data())
            .map_err(|err| RuntimeError::new(format!("Failed to deserialize: {err}")))
    }
}

/// An error attributable to the party with the element's ID, with associated data.
#[derive(displaydoc::Display)]
#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
#[displaydoc("Sender error (with secret reveal): {description}")]
pub struct SenderErrorWithReveal<SP: SessionParameters> {
    description: String,
    associated_data: AssociatedData<SP>,
}

impl<SP: SessionParameters> SenderErrorWithReveal<SP> {
    /// Creates a new error with the given description and an associated value (revealed data).
    pub fn new<T: Serialize + for<'de> Deserialize<'de>>(
        description: impl Into<String>,
        associated_value: T,
    ) -> Result<Self, RuntimeError> {
        let associated_data = match AssociatedData::new(associated_value) {
            Ok(data) => data,
            Err(error) => {
                return Err(error).or_with_context(|| "Failed to create associated data for a sender error".into());
            }
        };
        Ok(Self {
            description: description.into(),
            associated_data,
        })
    }

    pub(crate) fn associated_data(&self) -> &AssociatedData<SP> {
        &self.associated_data
    }
}

impl<SP: SessionParameters> From<SenderErrorWithReveal<SP>> for MaybeAttributableError<SenderErrorWithReveal<SP>> {
    fn from(source: SenderErrorWithReveal<SP>) -> Self {
        Self::Attributable(source)
    }
}

impl<SP: SessionParameters> core::error::Error for SenderErrorWithReveal<SP> {}

/// An error attributable to a third party (not the one that sent the triggering message), with associated data.
#[derive(displaydoc::Display)]
#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
#[displaydoc("Third party attributable error: {description}")]
pub struct ThirdPartyError<SP: SessionParameters> {
    guilty_party: SP::Verifier,
    description: String,
    associated_data: AssociatedData<SP>,
}

impl<SP: SessionParameters> ThirdPartyError<SP> {
    /// Creates a new error with the given description and an associated value (revealed data).
    pub fn new<T: Serialize + for<'de> Deserialize<'de>>(
        description: impl Into<String>,
        guilty_party: &SP::Verifier,
        associated_value: T,
    ) -> Result<Self, RuntimeError> {
        let associated_data = match AssociatedData::new(associated_value) {
            Ok(data) => data,
            Err(error) => {
                return Err(error)
                    .or_with_context(|| "Failed to create associated data for a third-party error".into());
            }
        };
        Ok(Self {
            guilty_party: guilty_party.clone(),
            description: description.into(),
            associated_data,
        })
    }

    pub(crate) fn unpack(self) -> (SP::Verifier, StoredThirdPartyError<SP>) {
        (
            self.guilty_party,
            StoredThirdPartyError {
                description: self.description,
                associated_data: self.associated_data,
            },
        )
    }
}

impl<SP: SessionParameters> From<ThirdPartyError<SP>> for MaybeAttributableError<ThirdPartyError<SP>> {
    fn from(source: ThirdPartyError<SP>) -> Self {
        Self::Attributable(source)
    }
}

impl<SP: SessionParameters> core::error::Error for ThirdPartyError<SP> {}

/// Guilty party is stored separately in [`Evidence`], this structure represents the rest of [`ThirdPartyError`].
#[derive(displaydoc::Display)]
#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
#[displaydoc("Third party attributable error: {description}")]
pub(crate) struct StoredThirdPartyError<SP: SessionParameters> {
    description: String,
    associated_data: AssociatedData<SP>,
}

impl<SP: SessionParameters> StoredThirdPartyError<SP> {
    pub(crate) fn associated_data(&self) -> &AssociatedData<SP> {
        &self.associated_data
    }
}
