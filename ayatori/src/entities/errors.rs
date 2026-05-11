use alloc::{format, string::String};
use core::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};

use super::value::SerializedValue;
use crate::{
    error::{Traceable, TracedError},
    traits::{SessionParameters, WireFormat},
};

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

    /// Indicates a runtime error that is unreachable in tests.
    #[track_caller]
    pub(crate) fn expect(description: impl Into<String>) -> Self {
        Self(TracedError::new(description))
    }
}

impl Traceable for RuntimeError {
    #[track_caller]
    fn with_context(self, context: impl Into<String>) -> Self {
        Self(self.0.with_context(context))
    }
}

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

#[derive(displaydoc::Display, Debug, Clone, Serialize, Deserialize)]
#[displaydoc("Sender error: {description}")]
pub(crate) struct SenderError {
    pub(crate) description: String,
}

/// An error during a mapping element computation that is attributable to the party with the element's ID.
#[derive(displaydoc::Display, Debug, Clone)]
pub struct SenderAttributableError(pub(crate) SenderAttributableErrorEnum);

#[derive(displaydoc::Display, Debug, Clone)]
pub(crate) enum SenderAttributableErrorEnum {
    #[displaydoc("{0}")]
    Unattributable(UnattributableError),
    #[displaydoc("{0}")]
    Attributable(SenderError),
}

impl From<RuntimeError> for SenderAttributableError {
    fn from(source: RuntimeError) -> Self {
        Self(SenderAttributableErrorEnum::Unattributable(source.into()))
    }
}

impl SenderAttributableError {
    /// Returns the [`UnattributableError::Spurious`] variant.
    pub fn spurious(description: impl Into<String>) -> Self {
        Self(SenderAttributableErrorEnum::Unattributable(
            SpuriousError::new(description).into(),
        ))
    }

    /// Returns the [`UnattributableError::Runtime`] variant.
    #[track_caller]
    pub fn runtime(description: impl Into<String>) -> Self {
        Self(SenderAttributableErrorEnum::Unattributable(
            RuntimeError::new(description).into(),
        ))
    }

    /// Creates a new error with the given description.
    pub fn new(description: impl Into<String>) -> Self {
        Self(SenderAttributableErrorEnum::Attributable(SenderError {
            description: description.into(),
        }))
    }
}

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
        SP::WireFormat::deserialize::<T>(self.serialized_value.as_ref())
            .map_err(|err| RuntimeError::new(format!("Failed to deserialize: {err}")))
    }
}

#[derive(displaydoc::Display)]
#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
#[displaydoc("Sender error (with secret reveal): {description}")]
pub(crate) struct SenderErrorWithReveal<SP: SessionParameters> {
    pub(crate) description: String,
    pub(crate) associated_data: AssociatedData<SP>,
}

/// An error during a mapping element computation that is attributable to the party with the element's ID,
/// and needs additional data to be revealed and stored in the evidence.
#[derive(displaydoc::Display)]
#[derive_where::derive_where(Debug, Clone)]
#[displaydoc("{0}")]
pub struct SenderAttributableErrorWithReveal<SP: SessionParameters>(
    pub(crate) SenderAttributableErrorWithRevealEnum<SP>,
);

#[derive(displaydoc::Display)]
#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum SenderAttributableErrorWithRevealEnum<SP: SessionParameters> {
    #[displaydoc("{0}")]
    Unattributable(UnattributableError),
    #[displaydoc("{0}")]
    Attributable(SenderErrorWithReveal<SP>),
}

impl<SP: SessionParameters> From<RuntimeError> for SenderAttributableErrorWithReveal<SP> {
    fn from(source: RuntimeError) -> Self {
        Self(SenderAttributableErrorWithRevealEnum::Unattributable(source.into()))
    }
}

impl<SP: SessionParameters> SenderAttributableErrorWithReveal<SP> {
    /// Returns the [`UnattributableError::Spurious`] variant.
    pub fn spurious(description: impl Into<String>) -> Self {
        Self(SenderAttributableErrorWithRevealEnum::Unattributable(
            SpuriousError::new(description).into(),
        ))
    }

    /// Returns the [`UnattributableError::Runtime`] variant.
    #[track_caller]
    pub fn runtime(description: impl Into<String>) -> Self {
        Self(SenderAttributableErrorWithRevealEnum::Unattributable(
            RuntimeError::new(description).into(),
        ))
    }

    /// Creates a new error with the given description and an associated value (revealed data).
    pub fn new<T: Serialize + for<'de> Deserialize<'de>>(description: impl Into<String>, associated_value: T) -> Self {
        let associated_data = match AssociatedData::new(associated_value) {
            Ok(data) => data,
            Err(error) => return Self::from(error),
        };
        Self(SenderAttributableErrorWithRevealEnum::Attributable(
            SenderErrorWithReveal {
                description: description.into(),
                associated_data,
            },
        ))
    }
}

#[derive(displaydoc::Display)]
#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
#[displaydoc("Third party attributable error: {description}")]
pub(crate) struct ThirdPartyError<SP: SessionParameters> {
    pub(crate) description: String,
    pub(crate) associated_data: AssociatedData<SP>,
}

/// An error during a mapping element computation that is attributable to a party with the ID
/// different from that of the element's.
#[derive(displaydoc::Display)]
#[derive_where::derive_where(Debug, Clone)]
#[displaydoc("{0}")]
pub struct ThirdPartyAttributableError<SP: SessionParameters>(pub(crate) ThirdPartyAttributableErrorEnum<SP>);

#[derive(displaydoc::Display)]
#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ThirdPartyAttributableErrorEnum<SP: SessionParameters> {
    #[displaydoc("{0}")]
    Unattributable(UnattributableError),
    #[displaydoc("{error}")]
    Attributable {
        guilty_party: SP::Verifier,
        error: ThirdPartyError<SP>,
    },
}

impl<SP: SessionParameters> From<RuntimeError> for ThirdPartyAttributableError<SP> {
    fn from(source: RuntimeError) -> Self {
        Self(ThirdPartyAttributableErrorEnum::Unattributable(source.into()))
    }
}

impl<SP: SessionParameters> ThirdPartyAttributableError<SP> {
    /// Returns the [`UnattributableError::Spurious`] variant.
    pub fn spurious(description: impl Into<String>) -> Self {
        Self(ThirdPartyAttributableErrorEnum::Unattributable(
            SpuriousError::new(description).into(),
        ))
    }

    /// Returns the [`UnattributableError::Runtime`] variant.
    #[track_caller]
    pub fn runtime(description: impl Into<String>) -> Self {
        Self(ThirdPartyAttributableErrorEnum::Unattributable(
            RuntimeError::new(description).into(),
        ))
    }

    /// Creates a new error with the given description and an associated value (revealed data).
    pub fn new<T: Serialize + for<'de> Deserialize<'de>>(
        description: impl Into<String>,
        guilty_party: &SP::Verifier,
        associated_value: T,
    ) -> Self {
        let associated_data = match AssociatedData::new(associated_value) {
            Ok(data) => data,
            Err(error) => return Self::from(error),
        };
        Self(ThirdPartyAttributableErrorEnum::Attributable {
            guilty_party: guilty_party.clone(),
            error: ThirdPartyError {
                description: description.into(),
                associated_data,
            },
        })
    }
}
