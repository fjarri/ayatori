use alloc::{format, string::String};
use core::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};

use super::value::SerializedValue;
use crate::traits::{SessionParameters, WireFormat};

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
    /// Creates a new error from anything castable to string.
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
pub struct RuntimeError(String);

impl RuntimeError {
    /// Creates a new error from anything castable to string.
    pub fn new(description: impl Into<String>) -> Self {
        Self(description.into())
    }

    /// Indicates a runtime error that is unreachable in tests.
    pub fn expect(description: impl Into<String>) -> Self {
        Self(description.into())
    }
}

#[derive(displaydoc::Display, Debug, Clone)]
pub enum UnattributableError {
    #[displaydoc("{0}")]
    Spurious(SpuriousError),
    #[displaydoc("{0}")]
    Runtime(RuntimeError),
}

impl From<RuntimeError> for UnattributableError {
    fn from(source: RuntimeError) -> Self {
        Self::Runtime(source)
    }
}

impl UnattributableError {
    pub fn spurious(description: impl Into<String>) -> Self {
        Self::Spurious(SpuriousError::new(description))
    }

    pub fn runtime(description: impl Into<String>) -> Self {
        Self::Runtime(RuntimeError::new(description))
    }
}

#[derive(displaydoc::Display, Debug, Clone, Serialize, Deserialize)]
#[displaydoc("Sender error: {description}")]
pub(crate) struct SenderError {
    pub(crate) description: String,
}

#[derive(displaydoc::Display, Debug, Clone)]
pub struct SenderAttributableError(pub(crate) SenderAttributableErrorEnum);

#[derive(displaydoc::Display, Debug, Clone)]
pub(crate) enum SenderAttributableErrorEnum {
    #[displaydoc("{0}")]
    Unattributable(UnattributableError),
    /// An error caused by an invalid description from another party.
    #[displaydoc("{0}")]
    Attributable(SenderError),
}

impl From<RuntimeError> for SenderAttributableError {
    fn from(source: RuntimeError) -> Self {
        Self(SenderAttributableErrorEnum::Unattributable(source.into()))
    }
}

impl SenderAttributableError {
    pub fn spurious(description: impl Into<String>) -> Self {
        Self(SenderAttributableErrorEnum::Unattributable(
            UnattributableError::spurious(description),
        ))
    }

    pub fn runtime(description: impl Into<String>) -> Self {
        Self(SenderAttributableErrorEnum::Unattributable(
            UnattributableError::runtime(description),
        ))
    }

    pub fn new(description: impl Into<String>) -> Self {
        Self(SenderAttributableErrorEnum::Attributable(SenderError {
            description: description.into(),
        }))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[derive_where::derive_where(Clone)]
pub struct AssociatedData<SP: SessionParameters> {
    serialized_value: SerializedValue,
    phantom: PhantomData<SP>,
}

impl<SP: SessionParameters> AssociatedData<SP> {
    pub(crate) fn new<T: Serialize + for<'de> Deserialize<'de>>(value: T) -> Result<Self, RuntimeError> {
        let serialized_value = SerializedValue::new(SP::WireFormat::serialize(value)?);
        Ok(Self {
            serialized_value,
            phantom: PhantomData,
        })
    }

    pub fn deserialize<T: for<'de> Deserialize<'de>>(&self) -> Result<T, RuntimeError> {
        SP::WireFormat::deserialize::<T>(self.serialized_value.as_ref())
            .map_err(|err| RuntimeError::new(format!("Failed to deserialize: {err}")))
    }
}

#[derive(displaydoc::Display, Debug, Clone, Serialize, Deserialize)]
#[displaydoc("Sender error (with secret reveal): {description}")]
pub(crate) struct SenderErrorWithReveal<SP: SessionParameters> {
    pub(crate) description: String,
    pub(crate) associated_data: AssociatedData<SP>,
}

#[derive(displaydoc::Display, Debug, Clone)]
pub struct SenderAttributableErrorWithReveal<SP: SessionParameters>(
    pub(crate) SenderAttributableErrorWithRevealEnum<SP>,
);

#[derive(displaydoc::Display, Debug, Clone)]
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
    pub fn spurious(description: impl Into<String>) -> Self {
        Self(SenderAttributableErrorWithRevealEnum::Unattributable(
            UnattributableError::spurious(description),
        ))
    }

    pub fn runtime(description: impl Into<String>) -> Self {
        Self(SenderAttributableErrorWithRevealEnum::Unattributable(
            UnattributableError::runtime(description),
        ))
    }

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

#[derive(displaydoc::Display, Debug, Serialize, Deserialize)]
#[derive_where::derive_where(Clone)]
#[displaydoc("Third party attributable error: {description}")]
pub(crate) struct ThirdPartyError<SP: SessionParameters> {
    pub(crate) description: String,
    pub(crate) associated_data: AssociatedData<SP>,
}

#[derive(displaydoc::Display, Debug)]
#[derive_where::derive_where(Clone)]
pub struct ThirdPartyAttributableError<SP: SessionParameters>(pub(crate) ThirdPartyAttributableErrorEnum<SP>);

#[derive(displaydoc::Display, Debug)]
#[derive_where::derive_where(Clone)]
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
    pub fn spurious(description: impl Into<String>) -> Self {
        Self(ThirdPartyAttributableErrorEnum::Unattributable(
            UnattributableError::spurious(description),
        ))
    }

    pub fn runtime(description: impl Into<String>) -> Self {
        Self(ThirdPartyAttributableErrorEnum::Unattributable(
            UnattributableError::runtime(description),
        ))
    }

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
