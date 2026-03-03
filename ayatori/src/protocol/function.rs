use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use core::fmt::{self, Debug, Display};

use serde::Serialize;
use signature::rand_core::CryptoRngCore;

use super::{
    args::Args,
    traits::{SessionParameters, WireFormat},
    value::{Erasable, SerializedValue, Value},
};
use crate::error::LocalError;

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

#[derive(Debug)]
pub struct ThirdPartyError<SP: SessionParameters>(pub(crate) ThirdPartyErrorEnum<SP>);

#[derive(Debug)]
pub(crate) enum ThirdPartyErrorEnum<SP: SessionParameters> {
    Local(LocalError),
    Error {
        guilty_party: SP::Verifier,
        associated_data: SerializedValue,
    },
}

impl<SP: SessionParameters> From<LocalError> for ThirdPartyError<SP> {
    fn from(source: LocalError) -> Self {
        Self(ThirdPartyErrorEnum::Local(source))
    }
}

impl<SP: SessionParameters> ThirdPartyError<SP> {
    pub fn new<T: Serialize>(guilty_party: &SP::Verifier, associated_value: T) -> Result<Self, LocalError> {
        let associated_data = SerializedValue::new(SP::WireFormat::serialize(associated_value)?);
        Ok(Self(ThirdPartyErrorEnum::Error {
            guilty_party: guilty_party.clone(),
            associated_data,
        }))
    }
}

macro_rules! define_function_type {
    ($type_name:ident<$generic_name:ident>, $error_type:ty $(, $arg_name:ident: $arg_type:ty )*) => {
        #[derive_where::derive_where(Clone)]
        pub(crate) struct $type_name<$generic_name: SessionParameters> {
            #[allow(clippy::type_complexity)]
            function: Arc<dyn Fn($($arg_type),*) -> Result<Value, $error_type>>,
            name: String,
        }

        impl<$generic_name: SessionParameters> Debug for $type_name<$generic_name> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(f, "{} {{ function: {} }}", stringify!($type_name), self.name)
            }
        }

        impl<$generic_name: SessionParameters> Display for $type_name<$generic_name> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(f, "{}", self.name)
            }
        }

        impl<$generic_name: SessionParameters> $type_name<$generic_name> {
            pub fn new<Ret: Erasable>(
                function: impl 'static + Fn($($arg_type),*) -> Result<Ret, $error_type>
            ) -> Self {
                let name = core::any::type_name_of_val(&function).to_string();
                Self::new_pre_erased(
                    name,
                    move |$($arg_name: $arg_type),*| function($($arg_name),*).map(Value::new)
                )
            }

            pub fn new_pre_erased(
                name: impl Into<String>,
                function: impl 'static + Fn($($arg_type),*) -> Result<Value, $error_type>,
            ) -> Self {
                let wrapped = Arc::new(function);
                Self {
                    function: wrapped,
                    name: name.into(),
                }
            }

            pub fn call(&self, $($arg_name: $arg_type),*) -> Result<Value, $error_type> {
                (self.function)($($arg_name),*)
            }
        }
    }
}

define_function_type!(
    InfallibleScalarFunction<SP>,
    LocalError,
    args: Args<SP>
);

define_function_type!(
    InfallibleScalarFunctionWithRng<SP>,
    LocalError,
    rng: &mut dyn CryptoRngCore, args: Args<SP>
);

define_function_type!(
    InfallibleArrayFunction<SP>,
    LocalError,
    id: &SP::Verifier, args: Args<SP>
);

define_function_type!(
    InfallibleArrayFunctionWithRng<SP>,
    LocalError,
    rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>
);

define_function_type!(
    SenderAttributableArrayFunction<SP>,
    SenderError,
    id: &SP::Verifier, args: Args<SP>
);

define_function_type!(
    ThirdPartyAttributableArrayFunction<SP>,
    ThirdPartyError<SP>,
    id: &SP::Verifier, args: Args<SP>
);

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ScalarFunction<SP: SessionParameters> {
    Infallible(InfallibleScalarFunction<SP>),
    InfallibleWithRng(InfallibleScalarFunctionWithRng<SP>),
}

impl<SP: SessionParameters> ScalarFunction<SP> {
    pub fn takes_rng(&self) -> bool {
        matches!(self, Self::InfallibleWithRng(_))
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ArrayFunction<SP: SessionParameters> {
    Infallible(InfallibleArrayFunction<SP>),
    InfallibleWithRng(InfallibleArrayFunctionWithRng<SP>),
    SenderAttributable(SenderAttributableArrayFunction<SP>),
    ThirdPartyAttributable(ThirdPartyAttributableArrayFunction<SP>),
}

impl<SP: SessionParameters> ArrayFunction<SP> {
    pub fn takes_rng(&self) -> bool {
        matches!(self, Self::InfallibleWithRng(_))
    }
}

impl<SP: SessionParameters> Display for ScalarFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::InfallibleWithRng(function) => write!(f, "{function}[RNG]"),
            Self::Infallible(function) => write!(f, "{function}"),
        }
    }
}

impl<SP: SessionParameters> Display for ArrayFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::InfallibleWithRng(function) => write!(f, "{function}[RNG]"),
            Self::Infallible(function) => write!(f, "{function}"),
            Self::SenderAttributable(function) => write!(f, "{function}"),
            Self::ThirdPartyAttributable(function) => write!(f, "{function}"),
        }
    }
}
