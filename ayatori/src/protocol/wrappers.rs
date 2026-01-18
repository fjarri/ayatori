use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::any::Any;
use core::fmt::{self, Debug, Display};

use rand_core::CryptoRng;

use super::node::{Args, PartyId, Protocol, Value};

pub(crate) struct WrappedFunction<Id: PartyId, P: Protocol<Id>> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(&P::SharedData, Args<Id>) -> Value>,
    name: String,
}

impl<Id: PartyId, P: Protocol<Id>> Debug for WrappedFunction<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedFunction {{ function: {} }}", self.name)
    }
}

impl<Id: PartyId, P: Protocol<Id>> Display for WrappedFunction<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<Id: PartyId, P: Protocol<Id>> Clone for WrappedFunction<Id, P> {
    fn clone(&self) -> Self {
        Self {
            function: self.function.clone(),
            name: self.name.clone(),
        }
    }
}

impl<Id: PartyId, P: Protocol<Id>> WrappedFunction<Id, P> {
    pub fn new<Ret: Any + Send + Sync>(function: impl 'static + Fn(&P::SharedData, Args<Id>) -> Ret) -> Self {
        let name = core::any::type_name_of_val(&function).to_string();
        let wrapped =
            Arc::new(move |shared_data: &P::SharedData, args: Args<Id>| Value::new(function(shared_data, args)));
        Self {
            function: wrapped,
            name,
        }
    }

    pub fn call(&self, shared_data: &P::SharedData, args: Args<Id>) -> Value {
        (self.function)(shared_data, args)
    }
}

pub(crate) struct WrappedArrayFunction<Id: PartyId, P: Protocol<Id>> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(&Id, &P::SharedData, Args<Id>) -> Value>,
    name: String,
}

impl<Id: PartyId, P: Protocol<Id>> Debug for WrappedArrayFunction<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedFunction {{ function: {} }}", self.name)
    }
}

impl<Id: PartyId, P: Protocol<Id>> Display for WrappedArrayFunction<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<Id: PartyId, P: Protocol<Id>> Clone for WrappedArrayFunction<Id, P> {
    fn clone(&self) -> Self {
        Self {
            function: self.function.clone(),
            name: self.name.clone(),
        }
    }
}

impl<Id: PartyId, P: Protocol<Id>> WrappedArrayFunction<Id, P> {
    pub fn new<Ret: Any + Send + Sync>(function: impl 'static + Fn(&Id, &P::SharedData, Args<Id>) -> Ret) -> Self {
        let name = core::any::type_name_of_val(&function).to_string();
        let wrapped = Arc::new(move |id: &Id, shared_data: &P::SharedData, args: Args<Id>| {
            Value::new(function(id, shared_data, args))
        });
        Self {
            function: wrapped,
            name,
        }
    }

    pub fn call(&self, id: &Id, shared_data: &P::SharedData, args: Args<Id>) -> Value {
        (self.function)(id, shared_data, args)
    }
}

pub(crate) struct WrappedFunctionPrivate<Id: PartyId, P: Protocol<Id>> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(&mut dyn CryptoRng, &P::SharedData, Args<Id>) -> Value>,
    name: String,
}

impl<Id: PartyId, P: Protocol<Id>> Debug for WrappedFunctionPrivate<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "WrappedFunctionPrivate {{ function: {} }}", self.name)
    }
}

impl<Id: PartyId, P: Protocol<Id>> Display for WrappedFunctionPrivate<Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.name)
    }
}

impl<Id: PartyId, P: Protocol<Id>> Clone for WrappedFunctionPrivate<Id, P> {
    fn clone(&self) -> Self {
        Self {
            function: self.function.clone(),
            name: self.name.clone(),
        }
    }
}

impl<Id: PartyId, P: Protocol<Id>> WrappedFunctionPrivate<Id, P> {
    pub fn new<Ret, F>(function: F) -> Self
    where
        F: 'static + Fn(&mut dyn CryptoRng, &P::SharedData, Args<Id>) -> Ret,
        Ret: Any + Send + Sync,
    {
        let name = core::any::type_name_of_val(&function).to_string();
        let wrapped = Arc::new(
            move |rng: &mut dyn CryptoRng, shared_data: &P::SharedData, args: Args<Id>| {
                Value::new(function(rng, shared_data, args))
            },
        );
        Self {
            function: wrapped,
            name,
        }
    }

    pub fn call(&self, rng: &mut impl CryptoRng, shared_data: &P::SharedData, args: Args<Id>) -> Value {
        (self.function)(rng, shared_data, args)
    }
}
