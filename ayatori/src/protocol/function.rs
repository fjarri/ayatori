use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use core::fmt::{self, Debug, Display};

use signature::rand_core::CryptoRngCore;

use super::{
    node::Args,
    traits::{Protocol, SessionParameters},
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

pub(crate) struct WrappedScalarFunction<SP: SessionParameters, P: Protocol<SP>> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(&P::SharedData, Args<SP>) -> Result<Value, ComputeError>>,
    name: String,
}

impl<SP: SessionParameters, P: Protocol<SP>> Debug for WrappedScalarFunction<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedScalarFunction {{ function: {} }}", self.name)
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Display for WrappedScalarFunction<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Clone for WrappedScalarFunction<SP, P> {
    fn clone(&self) -> Self {
        Self {
            function: self.function.clone(),
            name: self.name.clone(),
        }
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> WrappedScalarFunction<SP, P> {
    pub fn new<Ret: Erasable>(
        function: impl 'static + Fn(&P::SharedData, Args<SP>) -> Result<Ret, ComputeError>,
    ) -> Self {
        let name = core::any::type_name_of_val(&function).to_string();
        let wrapped =
            Arc::new(move |shared_data: &P::SharedData, args: Args<SP>| function(shared_data, args).map(Value::new));
        Self {
            function: wrapped,
            name,
        }
    }

    pub fn call(&self, shared_data: &P::SharedData, args: Args<SP>) -> Result<Value, ComputeError> {
        (self.function)(shared_data, args)
    }
}

pub(crate) struct WrappedArrayFunction<SP: SessionParameters, P: Protocol<SP>> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(&SP::Verifier, &P::SharedData, Args<SP>) -> Result<Value, ComputeError>>,
    name: String,
}

impl<SP: SessionParameters, P: Protocol<SP>> Debug for WrappedArrayFunction<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedScalarFunction {{ function: {} }}", self.name)
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Display for WrappedArrayFunction<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Clone for WrappedArrayFunction<SP, P> {
    fn clone(&self) -> Self {
        Self {
            function: self.function.clone(),
            name: self.name.clone(),
        }
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> WrappedArrayFunction<SP, P> {
    pub fn new<Ret: Erasable>(
        function: impl 'static + Fn(&SP::Verifier, &P::SharedData, Args<SP>) -> Result<Ret, ComputeError>,
    ) -> Self {
        let name = core::any::type_name_of_val(&function).to_string();
        Self::new_pre_erased(
            name,
            move |id: &SP::Verifier, shared_data: &P::SharedData, args: Args<SP>| {
                function(id, shared_data, args).map(Value::new)
            },
        )
    }

    pub(crate) fn new_pre_erased(
        name: impl Into<String>,
        function: impl 'static + Fn(&SP::Verifier, &P::SharedData, Args<SP>) -> Result<Value, ComputeError>,
    ) -> Self {
        let wrapped = Arc::new(function);
        Self {
            function: wrapped,
            name: name.into(),
        }
    }

    pub fn call(&self, id: &SP::Verifier, shared_data: &P::SharedData, args: Args<SP>) -> Result<Value, ComputeError> {
        (self.function)(id, shared_data, args)
    }
}

pub(crate) struct WrappedScalarFunctionPrivate<SP: SessionParameters, P: Protocol<SP>> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(&mut dyn CryptoRngCore, &P::SharedData, Args<SP>) -> Result<Value, ComputeError>>,
    name: String,
}

impl<SP: SessionParameters, P: Protocol<SP>> Debug for WrappedScalarFunctionPrivate<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedScalarFunctionPrivate {{ function: {} }}", self.name)
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Display for WrappedScalarFunctionPrivate<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Clone for WrappedScalarFunctionPrivate<SP, P> {
    fn clone(&self) -> Self {
        Self {
            function: self.function.clone(),
            name: self.name.clone(),
        }
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> WrappedScalarFunctionPrivate<SP, P> {
    pub fn new<Ret, F>(function: F) -> Self
    where
        F: 'static + Fn(&mut dyn CryptoRngCore, &P::SharedData, Args<SP>) -> Result<Ret, ComputeError>,
        Ret: Erasable,
    {
        let name = core::any::type_name_of_val(&function).to_string();
        let wrapped = Arc::new(
            move |rng: &mut dyn CryptoRngCore, shared_data: &P::SharedData, args: Args<SP>| {
                function(rng, shared_data, args).map(Value::new)
            },
        );
        Self {
            function: wrapped,
            name,
        }
    }

    pub fn call(
        &self,
        rng: &mut impl CryptoRngCore,
        shared_data: &P::SharedData,
        args: Args<SP>,
    ) -> Result<Value, ComputeError> {
        (self.function)(rng, shared_data, args)
    }
}

pub(crate) struct WrappedArrayFunctionPrivate<SP: SessionParameters, P: Protocol<SP>> {
    #[allow(clippy::type_complexity)]
    function:
        Arc<dyn Fn(&mut dyn CryptoRngCore, &SP::Verifier, &P::SharedData, Args<SP>) -> Result<Value, ComputeError>>,
    name: String,
}

impl<SP: SessionParameters, P: Protocol<SP>> Debug for WrappedArrayFunctionPrivate<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedScalarFunctionPrivate {{ function: {} }}", self.name)
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Display for WrappedArrayFunctionPrivate<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Clone for WrappedArrayFunctionPrivate<SP, P> {
    fn clone(&self) -> Self {
        Self {
            function: self.function.clone(),
            name: self.name.clone(),
        }
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> WrappedArrayFunctionPrivate<SP, P> {
    pub fn new<F, Ret: Erasable>(function: F) -> Self
    where
        F: 'static + Fn(&mut dyn CryptoRngCore, &SP::Verifier, &P::SharedData, Args<SP>) -> Result<Ret, ComputeError>,
    {
        let name = core::any::type_name_of_val(&function).to_string();
        Self::new_pre_erased(
            name,
            move |rng: &mut dyn CryptoRngCore, id: &SP::Verifier, shared_data: &P::SharedData, args: Args<SP>| {
                function(rng, id, shared_data, args).map(Value::new)
            },
        )
    }

    pub(crate) fn new_pre_erased<F>(name: impl Into<String>, function: F) -> Self
    where
        F: 'static + Fn(&mut dyn CryptoRngCore, &SP::Verifier, &P::SharedData, Args<SP>) -> Result<Value, ComputeError>,
    {
        let wrapped = Arc::new(function);
        Self {
            function: wrapped,
            name: name.into(),
        }
    }

    pub fn call(
        &self,
        rng: &mut impl CryptoRngCore,
        id: &SP::Verifier,
        shared_data: &P::SharedData,
        args: Args<SP>,
    ) -> Result<Value, ComputeError> {
        (self.function)(rng, id, shared_data, args)
    }
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub(crate) enum ScalarFunction<SP: SessionParameters, P: Protocol<SP>> {
    Public(WrappedScalarFunction<SP, P>),
    Private(WrappedScalarFunctionPrivate<SP, P>),
}

#[derive(Debug)]
#[derive_where::derive_where(Clone)]
pub(crate) enum ArrayFunction<SP: SessionParameters, P: Protocol<SP>> {
    Public(WrappedArrayFunction<SP, P>),
    Private(WrappedArrayFunctionPrivate<SP, P>),
}

impl<SP: SessionParameters, P: Protocol<SP>> Display for ScalarFunction<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Private(function) => write!(f, "{function}[PRIVATE]"),
            Self::Public(function) => write!(f, "{function}"),
        }
    }
}

impl<SP: SessionParameters, P: Protocol<SP>> Display for ArrayFunction<SP, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Private(function) => write!(f, "{function}[PRIVATE]"),
            Self::Public(function) => write!(f, "{function}"),
        }
    }
}
