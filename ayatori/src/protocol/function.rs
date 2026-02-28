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
pub struct SenderError(SenderErrorEnum);

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
pub struct ThirdPartyError<SP: SessionParameters>(ThirdPartyErrorEnum<SP>);

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

#[derive(Debug)]
pub(crate) enum ScalarFunctionError {
    Local(LocalError),
}

impl From<LocalError> for ScalarFunctionError {
    fn from(source: LocalError) -> Self {
        Self::Local(source)
    }
}

#[derive(Debug)]
pub(crate) enum ArrayFunctionError<SP: SessionParameters> {
    Local(LocalError),
    Sender,
    ThirdParty {
        guilty_party: SP::Verifier,
        // TODO (#7): will be used for provable failures.
        #[allow(dead_code)]
        associated_data: SerializedValue,
    },
}

impl<SP: SessionParameters> From<LocalError> for ArrayFunctionError<SP> {
    fn from(source: LocalError) -> Self {
        Self::Local(source)
    }
}

impl<SP: SessionParameters> From<SenderError> for ArrayFunctionError<SP> {
    fn from(source: SenderError) -> Self {
        match source.0 {
            SenderErrorEnum::Local(error) => Self::Local(error),
            SenderErrorEnum::Error => Self::Sender,
        }
    }
}

impl<SP: SessionParameters> From<ThirdPartyError<SP>> for ArrayFunctionError<SP> {
    fn from(source: ThirdPartyError<SP>) -> Self {
        match source.0 {
            ThirdPartyErrorEnum::Local(error) => Self::Local(error),
            ThirdPartyErrorEnum::Error {
                guilty_party,
                associated_data,
            } => Self::ThirdParty {
                guilty_party,
                associated_data,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ScalarFallibility {
    Infallible,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ArrayFallibility {
    Infallible,
    Sender,
    ThirdParty,
}

macro_rules! define_scalar_function_type {
    ($type_name:ident<$generic_name:ident> $(, $arg_name:ident: $arg_type:ty )*) => {
        #[derive_where::derive_where(Clone)]
        pub(crate) struct $type_name<$generic_name: SessionParameters> {
            #[allow(clippy::type_complexity)]
            function: Arc<dyn Fn($($arg_type),*) -> Result<Value, ScalarFunctionError>>,
            name: String,
            #[allow(unused)]
            fallibility: ScalarFallibility,
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
            pub fn new_infallible<Ret: Erasable>(
                function: impl 'static + Fn($($arg_type),*) -> Result<Ret, LocalError>
            ) -> Self {
                let name = core::any::type_name_of_val(&function).to_string();
                Self::new_pre_erased(
                    name,
                    ScalarFallibility::Infallible,
                    move |$($arg_name: $arg_type),*| Ok(function($($arg_name),*).map(Value::new)?)
                )
            }

            pub fn new_pre_erased(
                name: impl Into<String>,
                fallibility: ScalarFallibility,
                function: impl 'static + Fn($($arg_type),*) -> Result<Value, ScalarFunctionError>,
            ) -> Self {
                let wrapped = Arc::new(function);
                Self {
                    function: wrapped,
                    name: name.into(),
                    fallibility,
                }
            }

            pub fn call(&self, $($arg_name: $arg_type),*) -> Result<Value, ScalarFunctionError> {
                (self.function)($($arg_name),*)
            }
        }
    }
}

macro_rules! define_array_function_type {
    ($type_name:ident<$generic_name:ident> $(, $arg_name:ident: $arg_type:ty )*) => {
        #[derive_where::derive_where(Clone)]
        pub(crate) struct $type_name<$generic_name: SessionParameters> {
            #[allow(clippy::type_complexity)]
            function: Arc<dyn Fn($($arg_type),*) -> Result<Value, ArrayFunctionError<SP>>>,
            name: String,
            #[allow(unused)]
            fallibility: ArrayFallibility,
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
            pub fn new_infallible<Ret: Erasable>(
                function: impl 'static + Fn($($arg_type),*) -> Result<Ret, LocalError>
            ) -> Self {
                let name = core::any::type_name_of_val(&function).to_string();
                Self::new_pre_erased(
                    name,
                    ArrayFallibility::Infallible,
                    move |$($arg_name: $arg_type),*| Ok(function($($arg_name),*).map(Value::new)?)
                )
            }

            pub fn new_sender<Ret: Erasable>(
                function: impl 'static + Fn($($arg_type),*) -> Result<Ret, SenderError>
            ) -> Self {
                let name = core::any::type_name_of_val(&function).to_string();
                Self::new_pre_erased(
                    name,
                    ArrayFallibility::Sender,
                    move |$($arg_name: $arg_type),*| Ok(function($($arg_name),*).map(Value::new)?)
                )
            }

            pub fn new_third_party<Ret: Erasable>(
                function: impl 'static + Fn($($arg_type),*) -> Result<Ret, ThirdPartyError<SP>>
            ) -> Self {
                let name = core::any::type_name_of_val(&function).to_string();
                Self::new_pre_erased(
                    name,
                    ArrayFallibility::ThirdParty,
                    move |$($arg_name: $arg_type),*| Ok(function($($arg_name),*).map(Value::new)?)
                )
            }

            pub fn new_pre_erased(
                name: impl Into<String>,
                fallibility: ArrayFallibility,
                function: impl 'static + Fn($($arg_type),*) -> Result<Value, ArrayFunctionError<SP>>,
            ) -> Self {
                let wrapped = Arc::new(function);
                Self {
                    function: wrapped,
                    name: name.into(),
                    fallibility,
                }
            }

            pub fn call(&self, $($arg_name: $arg_type),*) -> Result<Value, ArrayFunctionError<SP>> {
                (self.function)($($arg_name),*)
            }
        }
    }
}

define_scalar_function_type!(
    WrappedScalarFunction<SP>,
    args: Args<SP>
);

define_scalar_function_type!(
    WrappedScalarFunctionWithRng<SP>,
    rng: &mut dyn CryptoRngCore, args: Args<SP>
);

define_array_function_type!(
    WrappedArrayFunction<SP>,
    id: &SP::Verifier, args: Args<SP>
);

define_array_function_type!(
    WrappedArrayFunctionWithRng<SP>,
    rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>
);

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ScalarFunction<SP: SessionParameters> {
    NoRng(WrappedScalarFunction<SP>),
    WithRng(WrappedScalarFunctionWithRng<SP>),
}

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ArrayFunction<SP: SessionParameters> {
    NoRng(WrappedArrayFunction<SP>),
    WithRng(WrappedArrayFunctionWithRng<SP>),
}

impl<SP: SessionParameters> Display for ScalarFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::WithRng(function) => write!(f, "{function}[RNG]"),
            Self::NoRng(function) => write!(f, "{function}"),
        }
    }
}

impl<SP: SessionParameters> Display for ArrayFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::WithRng(function) => write!(f, "{function}[RNG]"),
            Self::NoRng(function) => write!(f, "{function}"),
        }
    }
}
