use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
};
use core::{
    fmt::{self, Debug, Display},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};
use signature::rand_core::CryptoRngCore;

use super::{
    args::{Args, DeserializeArgs, SerializeArgs},
    session_id::SessionId,
    value::{Erasable, SerializedValue, Value},
};
use crate::{
    errors::LocalError,
    traits::{SessionParameters, WireFormat},
};

#[derive(Debug, Default)]
pub struct SenderError(pub(crate) SenderErrorEnum);

#[derive(Debug, Default)]
pub(crate) enum SenderErrorEnum {
    Local(LocalError),
    #[default]
    Error,
}

impl From<LocalError> for SenderError {
    fn from(source: LocalError) -> Self {
        Self(SenderErrorEnum::Local(source))
    }
}

impl SenderError {
    pub fn new() -> Self {
        Self(SenderErrorEnum::Error)
    }
}

#[derive(displaydoc::Display, Debug, Clone)]
pub enum EvidenceVerdict {
    #[displaydoc("Valid evidence")]
    Valid,
    #[displaydoc("Invalid evidence: {0}")]
    Invalid(String),
}

impl EvidenceVerdict {
    pub fn valid() -> Self {
        Self::Valid
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[derive_where::derive_where(Clone)]
pub struct AssociatedData<SP: SessionParameters> {
    serialized_value: SerializedValue,
    phantom: PhantomData<SP>,
}

impl<SP: SessionParameters> AssociatedData<SP> {
    pub fn new<T: Serialize + for<'de> Deserialize<'de>>(value: T) -> Result<Self, LocalError> {
        let serialized_value = SerializedValue::new(SP::WireFormat::serialize(value)?);
        Ok(Self {
            serialized_value,
            phantom: PhantomData,
        })
    }

    pub fn deserialize<T: for<'de> Deserialize<'de>>(&self) -> Result<T, LocalError> {
        SP::WireFormat::deserialize::<T>(self.serialized_value.as_ref())
            .map_err(|err| LocalError::new(format!("Failed to deserialize: {err}")))
    }
}

#[derive(Debug)]
pub struct SenderErrorWithInfo<SP: SessionParameters>(pub(crate) SenderErrorWithInfoEnum<SP>);

#[derive(Debug)]
pub(crate) enum SenderErrorWithInfoEnum<SP: SessionParameters> {
    Local(LocalError),
    Error(AssociatedData<SP>),
}

impl<SP: SessionParameters> From<LocalError> for SenderErrorWithInfo<SP> {
    fn from(source: LocalError) -> Self {
        Self(SenderErrorWithInfoEnum::Local(source))
    }
}

impl<SP: SessionParameters> SenderErrorWithInfo<SP> {
    pub fn new<T: Serialize + for<'de> Deserialize<'de>>(associated_value: T) -> Result<Self, LocalError> {
        let associated_data = AssociatedData::new(associated_value)?;
        Ok(Self(SenderErrorWithInfoEnum::Error(associated_data)))
    }
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub struct ThirdPartyError<SP: SessionParameters>(pub(crate) ThirdPartyErrorEnum<SP>);

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub(crate) enum ThirdPartyErrorEnum<SP: SessionParameters> {
    Local(LocalError),
    Error {
        guilty_party: SP::Verifier,
        associated_data: AssociatedData<SP>,
    },
}

impl<SP: SessionParameters> From<LocalError> for ThirdPartyError<SP> {
    fn from(source: LocalError) -> Self {
        Self(ThirdPartyErrorEnum::Local(source))
    }
}

impl<SP: SessionParameters> ThirdPartyError<SP> {
    pub fn new<T: Serialize + for<'de> Deserialize<'de>>(
        guilty_party: &SP::Verifier,
        associated_value: T,
    ) -> Result<Self, LocalError> {
        let associated_data = AssociatedData::new(associated_value)?;
        Ok(Self(ThirdPartyErrorEnum::Error {
            guilty_party: guilty_party.clone(),
            associated_data,
        }))
    }
}

macro_rules! define_function_type_common {
    ($type_name:ident<$SP:ident>, ($($arg_name:ident: $arg_type:ty),+) -> Result<$return_type:ty, $error_type:ty> ) => {
        #[derive_where::derive_where(Clone)]
        pub(crate) struct $type_name<$SP: SessionParameters> {
            #[allow(clippy::type_complexity)]
            function: Arc<dyn Fn($($arg_type),*) -> Result<$return_type, $error_type>>,
            name: String,
        }

        impl<$SP: SessionParameters> Debug for $type_name<$SP> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(f, "{} {{ function: {} }}", stringify!($type_name), self.name)
            }
        }

        impl<$SP: SessionParameters> Display for $type_name<$SP> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(f, "{}", self.name)
            }
        }

        impl<$SP: SessionParameters> $type_name<$SP> {
            pub fn new_with_name(
                name: impl Into<String>,
                function: impl 'static + Fn($($arg_type),*) -> Result<$return_type, $error_type>,
            ) -> Self {
                let wrapped = Arc::new(function);
                Self {
                    function: wrapped,
                    name: name.into(),
                }
            }


            pub fn call(&self, $($arg_name: $arg_type),*) -> Result<$return_type, $error_type> {
                (self.function)($($arg_name),*)
            }
        }
    }
}

macro_rules! define_erased_function_type {
    ($type_name:ident<$SP:ident>, ($($arg_name:ident: $arg_type:ty),+) -> Result<$return_type:ty, $error_type:ty> ) => {

        define_function_type_common!($type_name<$SP>, ($($arg_name: $arg_type),*) -> Result<$return_type, $error_type>);

        impl<$SP: SessionParameters> $type_name<$SP> {
            pub fn new(
                function: impl 'static + Fn($($arg_type),*) -> Result<$return_type, $error_type>,
            ) -> Self {
                let name = core::any::type_name_of_val(&function).to_string();
                Self::new_with_name(name, function)
            }
        }
    }
}

macro_rules! define_typed_function_type {
    ($type_name:ident<$SP:ident>, ($($arg_name:ident: $arg_type:ty),+) -> $error_type:ty ) => {

        define_function_type_common!($type_name<$SP>, ($($arg_name: $arg_type),*) -> Result<Value, $error_type>);

        impl<$SP: SessionParameters> $type_name<$SP> {
            pub fn new_erased<Ret: Erasable>(
                function: impl 'static + Fn($($arg_type),*) -> Result<Ret, $error_type>
            ) -> Self {
                let name = core::any::type_name_of_val(&function).to_string();
                Self::new_with_name(
                    name,
                    move |$($arg_name: $arg_type),*| function($($arg_name),*).map(Value::new)
                )
            }
        }
    }
}

define_typed_function_type!(
    UnattributableScalarFunction<SP>,
    (args: &Args<SP>) -> LocalError
);

define_typed_function_type!(
    UnattributableScalarFunctionWithRng<SP>,
    (rng: &mut dyn CryptoRngCore, args: &Args<SP>) -> LocalError
);

define_typed_function_type!(
    UnattributableMappingFunction<SP>,
    (id: &SP::Verifier, args: &Args<SP>) -> LocalError
);

define_typed_function_type!(
    UnattributableMappingFunctionWithRng<SP>,
    (rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: &Args<SP>) -> LocalError
);

define_typed_function_type!(
    SenderAttributableMappingFunction<SP>,
    (id: &SP::Verifier, args: &Args<SP>) -> SenderError
);

define_typed_function_type!(
    SenderAttributableWithInfoMappingFunction<SP>,
    (id: &SP::Verifier, args: &Args<SP>) -> SenderErrorWithInfo<SP>
);

define_typed_function_type!(
    ThirdPartyAttributableMappingFunction<SP>,
    (id: &SP::Verifier, args: &Args<SP>) -> ThirdPartyError<SP>
);

define_erased_function_type!(
    ThirdPartyAttributableVerificationFunction<SP>,
    (guilty_party: &SP::Verifier, session_id: &SessionId<SP>, associated_data: &AssociatedData<SP>) -> Result<EvidenceVerdict, LocalError>
);

define_erased_function_type!(
    EvidenceVerificationFunction<SP>,
    (guilty_party: &SP::Verifier, args: &Args<SP>, associated_data: &AssociatedData<SP>) -> Result<EvidenceVerdict, LocalError>
);

define_erased_function_type!(
    SerializeAndSignFunction<SP>,
    (rng: &mut dyn CryptoRngCore, destination: &SP::Verifier, args: &SerializeArgs<SP>) -> Result<Value, LocalError>
);

define_erased_function_type!(
    DeserializeFunction<SP>,
    (args: &DeserializeArgs<SP>) -> Result<Value, SenderError>
);

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ScalarFunction<SP: SessionParameters> {
    Unattributable(UnattributableScalarFunction<SP>),
    UnattributableWithRng(UnattributableScalarFunctionWithRng<SP>),
}

impl<SP: SessionParameters> ScalarFunction<SP> {
    pub fn is_reproducible(&self) -> bool {
        !matches!(self, Self::UnattributableWithRng(_))
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum MappingFunction<SP: SessionParameters> {
    Unattributable(UnattributableMappingFunction<SP>),
    UnattributableWithRng(UnattributableMappingFunctionWithRng<SP>),
    SenderAttributable(SenderAttributableMappingFunction<SP>),
    SenderAttributableWithInfo(SenderAttributableWithInfoMappingFunction<SP>),
    ThirdPartyAttributable {
        function: ThirdPartyAttributableMappingFunction<SP>,
        verification: ThirdPartyAttributableVerificationFunction<SP>,
    },
}

impl<SP: SessionParameters> MappingFunction<SP> {
    pub fn is_reproducible(&self) -> bool {
        !matches!(self, Self::UnattributableWithRng(_))
    }
}

impl<SP: SessionParameters> Display for ScalarFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::UnattributableWithRng(function) => write!(f, "{function}[RNG]"),
            Self::Unattributable(function) => write!(f, "{function}"),
        }
    }
}

impl<SP: SessionParameters> Display for MappingFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::UnattributableWithRng(function) => write!(f, "{function}[RNG]"),
            Self::Unattributable(function) => write!(f, "{function}"),
            Self::SenderAttributable(function) => write!(f, "{function}"),
            Self::SenderAttributableWithInfo(function) => write!(f, "{function}"),
            Self::ThirdPartyAttributable { function, .. } => write!(f, "{function}"),
        }
    }
}
