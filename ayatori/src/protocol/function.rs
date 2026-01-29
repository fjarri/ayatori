use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use core::fmt::{self, Debug, Display};

use signature::rand_core::CryptoRngCore;

use super::{
    node::Args,
    traits::SessionParameters,
    value::{Erasable, Value},
};
use crate::error::LocalError;

#[derive(Debug)]
pub enum ComputeError {
    Local(LocalError),
    Data,
}

impl From<LocalError> for ComputeError {
    fn from(source: LocalError) -> Self {
        Self::Local(source)
    }
}

#[derive_where::derive_where(Clone)]
pub(crate) struct WrappedScalarFunction<SP: SessionParameters> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(Args<SP>) -> Result<Value, ComputeError>>,
    name: String,
}

impl<SP: SessionParameters> Debug for WrappedScalarFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedScalarFunction {{ function: {} }}", self.name)
    }
}

impl<SP: SessionParameters> Display for WrappedScalarFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<SP: SessionParameters> WrappedScalarFunction<SP> {
    pub fn new<Ret: Erasable>(function: impl 'static + Fn(Args<SP>) -> Result<Ret, ComputeError>) -> Self {
        let name = core::any::type_name_of_val(&function).to_string();
        Self::new_pre_erased(name, move |args: Args<SP>| function(args).map(Value::new))
    }

    pub fn new_pre_erased(
        name: impl Into<String>,
        function: impl 'static + Fn(Args<SP>) -> Result<Value, ComputeError>,
    ) -> Self {
        let wrapped = Arc::new(function);
        Self {
            function: wrapped,
            name: name.into(),
        }
    }

    pub fn call(&self, args: Args<SP>) -> Result<Value, ComputeError> {
        (self.function)(args)
    }
}

#[derive_where::derive_where(Clone)]
pub(crate) struct WrappedArrayFunction<SP: SessionParameters> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(&SP::Verifier, Args<SP>) -> Result<Value, ComputeError>>,
    name: String,
}

impl<SP: SessionParameters> Debug for WrappedArrayFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedScalarFunction {{ function: {} }}", self.name)
    }
}

impl<SP: SessionParameters> Display for WrappedArrayFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<SP: SessionParameters> WrappedArrayFunction<SP> {
    pub fn new<Ret: Erasable>(
        function: impl 'static + Fn(&SP::Verifier, Args<SP>) -> Result<Ret, ComputeError>,
    ) -> Self {
        let name = core::any::type_name_of_val(&function).to_string();
        Self::new_pre_erased(name, move |id: &SP::Verifier, args: Args<SP>| {
            function(id, args).map(Value::new)
        })
    }

    pub(crate) fn new_pre_erased(
        name: impl Into<String>,
        function: impl 'static + Fn(&SP::Verifier, Args<SP>) -> Result<Value, ComputeError>,
    ) -> Self {
        let wrapped = Arc::new(function);
        Self {
            function: wrapped,
            name: name.into(),
        }
    }

    pub fn call(&self, id: &SP::Verifier, args: Args<SP>) -> Result<Value, ComputeError> {
        (self.function)(id, args)
    }
}

#[derive_where::derive_where(Clone)]
pub(crate) struct WrappedScalarFunctionPrivate<SP: SessionParameters> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(&mut dyn CryptoRngCore, Args<SP>) -> Result<Value, ComputeError>>,
    name: String,
}

impl<SP: SessionParameters> Debug for WrappedScalarFunctionPrivate<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedScalarFunctionPrivate {{ function: {} }}", self.name)
    }
}

impl<SP: SessionParameters> Display for WrappedScalarFunctionPrivate<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<SP: SessionParameters> WrappedScalarFunctionPrivate<SP> {
    pub fn new<Ret, F>(function: F) -> Self
    where
        F: 'static + Fn(&mut dyn CryptoRngCore, Args<SP>) -> Result<Ret, ComputeError>,
        Ret: Erasable,
    {
        let name = core::any::type_name_of_val(&function).to_string();
        let wrapped = Arc::new(move |rng: &mut dyn CryptoRngCore, args: Args<SP>| function(rng, args).map(Value::new));
        Self {
            function: wrapped,
            name,
        }
    }

    pub fn call(&self, rng: &mut impl CryptoRngCore, args: Args<SP>) -> Result<Value, ComputeError> {
        (self.function)(rng, args)
    }
}

#[derive_where::derive_where(Clone)]
pub(crate) struct WrappedArrayFunctionPrivate<SP: SessionParameters> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(&mut dyn CryptoRngCore, &SP::Verifier, Args<SP>) -> Result<Value, ComputeError>>,
    name: String,
}

impl<SP: SessionParameters> Debug for WrappedArrayFunctionPrivate<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedScalarFunctionPrivate {{ function: {} }}", self.name)
    }
}

impl<SP: SessionParameters> Display for WrappedArrayFunctionPrivate<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<SP: SessionParameters> WrappedArrayFunctionPrivate<SP> {
    pub fn new<F, Ret: Erasable>(function: F) -> Self
    where
        F: 'static + Fn(&mut dyn CryptoRngCore, &SP::Verifier, Args<SP>) -> Result<Ret, ComputeError>,
    {
        let name = core::any::type_name_of_val(&function).to_string();
        Self::new_pre_erased(
            name,
            move |rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>| {
                function(rng, id, args).map(Value::new)
            },
        )
    }

    pub(crate) fn new_pre_erased<F>(name: impl Into<String>, function: F) -> Self
    where
        F: 'static + Fn(&mut dyn CryptoRngCore, &SP::Verifier, Args<SP>) -> Result<Value, ComputeError>,
    {
        let wrapped = Arc::new(function);
        Self {
            function: wrapped,
            name: name.into(),
        }
    }

    pub fn call(&self, rng: &mut impl CryptoRngCore, id: &SP::Verifier, args: Args<SP>) -> Result<Value, ComputeError> {
        (self.function)(rng, id, args)
    }
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub(crate) enum ScalarFunction<SP: SessionParameters> {
    Public(WrappedScalarFunction<SP>),
    Private(WrappedScalarFunctionPrivate<SP>),
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
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
