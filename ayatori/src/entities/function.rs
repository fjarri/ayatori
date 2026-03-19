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
    args::Args,
    value::{Erasable, SerializedValue, Value},
};
use crate::{
    errors::LocalError,
    execution::{EvidenceError, SessionId},
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct ThirdPartyError<SP: SessionParameters>(pub(crate) ThirdPartyErrorEnum<SP>);

#[derive(Debug)]
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

macro_rules! define_function_type_erased {
    ($type_name:ident<$SP:ident>, ($($arg_name:ident: $arg_type:ty),+) -> $error_type:ty ) => {
        #[derive_where::derive_where(Clone)]
        pub(crate) struct $type_name<$SP: SessionParameters> {
            #[allow(clippy::type_complexity)]
            function: Arc<dyn Fn($($arg_type),*) -> Result<Value, $error_type>>,
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

macro_rules! define_function_type {
    ($type_name:ident<$SP:ident>, ($($arg_name:ident: $arg_type:ty),+) -> $error_type:ty ) => {

        define_function_type_erased!($type_name<$SP>, ($($arg_name: $arg_type),*) -> $error_type);

        impl<$SP: SessionParameters> $type_name<$SP> {
            pub fn new<Ret: Erasable>(
                function: impl 'static + Fn($($arg_type),*) -> Result<Ret, $error_type>
            ) -> Self {
                let name = core::any::type_name_of_val(&function).to_string();
                Self::new_pre_erased(
                    name,
                    move |$($arg_name: $arg_type),*| function($($arg_name),*).map(Value::new)
                )
            }
        }
    }
}

define_function_type!(
    InfallibleScalarFunction<SP>,
    (args: Args<SP>) -> LocalError
);

define_function_type!(
    InfallibleScalarFunctionWithRng<SP>,
    (rng: &mut dyn CryptoRngCore, args: Args<SP>) -> LocalError
);

define_function_type!(
    InfallibleMappingFunction<SP>,
    (id: &SP::Verifier, args: Args<SP>) -> LocalError
);

define_function_type!(
    InfallibleMappingFunctionWithRng<SP>,
    (rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: Args<SP>) -> LocalError
);

define_function_type_erased!(
    InfallibleMappingFunctionWithSigner<SP>,
    (rng: &mut dyn CryptoRngCore, signer: &SP::Signer, id: &SP::Verifier, args: Args<SP>) -> LocalError
);

define_function_type!(
    SenderAttributableMappingFunction<SP>,
    (id: &SP::Verifier, args: Args<SP>) -> SenderError
);

define_function_type!(
    ThirdPartyAttributableMappingFunction<SP>,
    (id: &SP::Verifier, args: Args<SP>) -> ThirdPartyError<SP>
);

#[derive_where::derive_where(Clone)]
pub(crate) struct ThirdPartyAttributableVerificationFunction<SP: SessionParameters> {
    #[allow(clippy::type_complexity)]
    function: Arc<dyn Fn(&SessionId<SP>, &SP::Verifier, &AssociatedData<SP>) -> Result<(), EvidenceError>>,
    name: String,
}

impl<SP: SessionParameters> ThirdPartyAttributableVerificationFunction<SP> {
    pub fn new(
        function: impl 'static + Fn(&SessionId<SP>, &SP::Verifier, &AssociatedData<SP>) -> Result<(), EvidenceError>,
    ) -> Self {
        let name = core::any::type_name_of_val(&function).to_string();
        Self {
            name,
            function: Arc::new(function),
        }
    }

    pub fn call(
        &self,
        session_id: &SessionId<SP>,
        guilty_party: &SP::Verifier,
        associated_data: &AssociatedData<SP>,
    ) -> Result<(), EvidenceError> {
        (self.function)(session_id, guilty_party, associated_data)
    }
}

impl<SP: SessionParameters> Debug for ThirdPartyAttributableVerificationFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "ThirdPartyAttributableVerificationFunction {{ function: {} }}",
            self.name
        )
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ScalarFunction<SP: SessionParameters> {
    Infallible(InfallibleScalarFunction<SP>),
    InfallibleWithRng(InfallibleScalarFunctionWithRng<SP>),
}

impl<SP: SessionParameters> ScalarFunction<SP> {
    pub fn is_reproducible(&self) -> bool {
        !matches!(self, Self::InfallibleWithRng(_))
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum MappingFunction<SP: SessionParameters> {
    Infallible(InfallibleMappingFunction<SP>),
    InfallibleWithRng(InfallibleMappingFunctionWithRng<SP>),
    InfallibleWithSigner(InfallibleMappingFunctionWithSigner<SP>),
    SenderAttributable(SenderAttributableMappingFunction<SP>),
    ThirdPartyAttributable {
        function: ThirdPartyAttributableMappingFunction<SP>,
        verification: ThirdPartyAttributableVerificationFunction<SP>,
    },
}

impl<SP: SessionParameters> MappingFunction<SP> {
    pub fn is_reproducible(&self) -> bool {
        !matches!(self, Self::InfallibleWithRng(_) | Self::InfallibleWithSigner(_))
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

impl<SP: SessionParameters> Display for MappingFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::InfallibleWithRng(function) => write!(f, "{function}[RNG]"),
            Self::InfallibleWithSigner(function) => write!(f, "{function}[Signer]"),
            Self::Infallible(function) => write!(f, "{function}"),
            Self::SenderAttributable(function) => write!(f, "{function}"),
            Self::ThirdPartyAttributable { function, .. } => write!(f, "{function}"),
        }
    }
}
