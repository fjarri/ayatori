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

#[derive(Debug)]
pub struct ComputeError<SP: SessionParameters>(pub(crate) ComputeErrorEnum<SP>);

#[derive(Debug)]
pub(crate) enum ComputeErrorEnum<SP: SessionParameters> {
    Local(LocalError),
    Data,
    ThirdParty {
        guilty_party: SP::Verifier,
        // TODO (#7): will be used for provable failures.
        #[allow(dead_code)]
        associated_data: SerializedValue,
    },
}

impl<SP: SessionParameters> From<LocalError> for ComputeError<SP> {
    fn from(source: LocalError) -> Self {
        Self(ComputeErrorEnum::Local(source))
    }
}

impl<SP: SessionParameters> ComputeError<SP> {
    pub fn local(error: LocalError) -> Self {
        Self(ComputeErrorEnum::Local(error))
    }

    pub fn sender() -> Self {
        Self(ComputeErrorEnum::Data)
    }

    pub fn third_party<T: Serialize>(guilty_party: &SP::Verifier, associated_value: T) -> Result<Self, LocalError> {
        let associated_data = SerializedValue::new(SP::WireFormat::serialize(associated_value)?);
        Ok(Self(ComputeErrorEnum::ThirdParty {
            guilty_party: guilty_party.clone(),
            associated_data,
        }))
    }
}

macro_rules! define_function_type {
    ($type_name:ident<$generic_name:ident> $(, $arg_name:ident: $arg_type:ty )*) => {
        #[derive_where::derive_where(Clone)]
        pub(crate) struct $type_name<$generic_name: SessionParameters> {
            #[allow(clippy::type_complexity)]
            function: Arc<dyn Fn($($arg_type),*) -> Result<Value, ComputeError<SP>>>,
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
            pub fn new<Ret: Erasable>(function: impl 'static + Fn($($arg_type),*) -> Result<Ret, ComputeError<SP>>) -> Self {
                let name = core::any::type_name_of_val(&function).to_string();
                Self::new_pre_erased(name, move |$($arg_name: $arg_type),*| function($($arg_name),*).map(Value::new))
            }

            pub fn new_pre_erased(
                name: impl Into<String>,
                function: impl 'static + Fn($($arg_type),*) -> Result<Value, ComputeError<SP>>,
            ) -> Self {
                let wrapped = Arc::new(function);
                Self {
                    function: wrapped,
                    name: name.into(),
                }
            }

            pub fn call(&self, $($arg_name: $arg_type),*) -> Result<Value, ComputeError<SP>> {
                (self.function)($($arg_name),*)
            }
        }
    }
}

define_function_type!(WrappedScalarFunction<SP>, args: Args<SP>);
define_function_type!(WrappedScalarFunctionPrivate<SP>, rng: &mut dyn CryptoRngCore, args: Args<SP>);
define_function_type!(WrappedArrayFunction<SP>, id: &SP::Verifier, args: Args<SP>);
define_function_type!(WrappedArrayFunctionPrivate<SP>, rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>);

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ScalarFunction<SP: SessionParameters> {
    Public(WrappedScalarFunction<SP>),
    Private(WrappedScalarFunctionPrivate<SP>),
}

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ArrayFunction<SP: SessionParameters> {
    Public(WrappedArrayFunction<SP>),
    Private(WrappedArrayFunctionPrivate<SP>),
}

impl<SP: SessionParameters> Display for ScalarFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Private(function) => write!(f, "{function}[PRIVATE]"),
            Self::Public(function) => write!(f, "{function}"),
        }
    }
}

impl<SP: SessionParameters> Display for ArrayFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Private(function) => write!(f, "{function}[PRIVATE]"),
            Self::Public(function) => write!(f, "{function}"),
        }
    }
}
