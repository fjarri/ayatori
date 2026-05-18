use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use core::fmt::{self, Debug, Display};

use signature::rand_core::CryptoRngCore;

use super::{
    args::{Args, DeserializeArgs, SerializeArgs},
    errors::{
        AssociatedData, MaybeAttributableError, RuntimeError, SenderError, SenderErrorWithReveal, ThirdPartyError,
        UnattributableError,
    },
    session_id::SessionId,
    value::{Erasable, Value},
};
use crate::traits::SessionParameters;

/// The result of checking an evidence of malicious behavior of a protocol participant.
#[derive(displaydoc::Display, Debug, Clone)]
pub enum EvidenceVerdict {
    /// The evidence was found to be conclusive.
    #[displaydoc("Valid evidence")]
    Valid,
    /// There were problems with the evidence (missing data, incorrectly signed messages,
    /// the data was found to be self-consistent and not leading to failures etc).
    #[displaydoc("Invalid evidence: {0}")]
    Invalid(String),
}

impl EvidenceVerdict {
    /// Creates a new "valid" verdict.
    #[must_use]
    pub fn valid() -> Self {
        Self::Valid
    }

    /// Creates a new "invalid" verdict with an associated description.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

macro_rules! define_function_type_common {
    ($type_name:ident<$SP:ident>, ($($arg_name:ident: $arg_type:ty),+) -> Result<$return_type:ty, $error_type:ty> ) => {
        #[derive_where::derive_where(Clone)]
        pub(crate) struct $type_name<$SP: SessionParameters> {
            function: Arc<dyn Fn($($arg_type),*) -> Result<$return_type, $error_type> + Send + Sync>,
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
                function: impl 'static + Send + Sync + Fn($($arg_type),*) -> Result<$return_type, $error_type>,
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
                function: impl 'static + Send + Sync + Fn($($arg_type),*) -> Result<$return_type, $error_type>,
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
                function: impl 'static + Send + Sync + Fn($($arg_type),*) -> Result<Ret, $error_type>
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
    (args: &Args<SP>) -> UnattributableError
);

define_erased_function_type!(
    UnattributableOptionalScalarFunction<SP>,
    (args: &Args<SP>) -> Result<Option<Value>, RuntimeError>
);

define_typed_function_type!(
    UnattributableScalarFunctionWithRng<SP>,
    (rng: &mut dyn CryptoRngCore, args: &Args<SP>) -> UnattributableError
);

define_typed_function_type!(
    UnattributableMappingFunction<SP>,
    (id: &SP::Verifier, args: &Args<SP>) -> UnattributableError
);

define_typed_function_type!(
    UnattributableMappingFunctionWithRng<SP>,
    (rng: &mut dyn CryptoRngCore, id: &SP::Verifier, args: &Args<SP>) -> UnattributableError
);

define_typed_function_type!(
    SenderAttributableMappingFunction<SP>,
    (id: &SP::Verifier, args: &Args<SP>) -> MaybeAttributableError<SenderError>
);

define_typed_function_type!(
    SenderAttributableWithRevealMappingFunction<SP>,
    (id: &SP::Verifier, args: &Args<SP>) -> MaybeAttributableError<SenderErrorWithReveal<SP>>
);

define_typed_function_type!(
    ThirdPartyAttributableMappingFunction<SP>,
    (id: &SP::Verifier, args: &Args<SP>) -> MaybeAttributableError<ThirdPartyError<SP>>
);

define_erased_function_type!(
    ThirdPartyAttributableVerificationFunction<SP>,
    (guilty_party: &SP::Verifier, session_id: &SessionId<SP>, associated_data: &AssociatedData<SP>)
    -> Result<EvidenceVerdict, RuntimeError>
);

define_erased_function_type!(
    SenderAttributableVerificationFunction<SP>,
    (guilty_party: &SP::Verifier, args: &Args<SP>, associated_data: &AssociatedData<SP>)
    -> Result<EvidenceVerdict, RuntimeError>
);

define_erased_function_type!(
    SerializeAndSignFunction<SP>,
    (rng: &mut dyn CryptoRngCore, destination: &SP::Verifier, args: &SerializeArgs<SP>) -> Result<Value, RuntimeError>
);

define_erased_function_type!(
    DeserializeFunction<SP>,
    (args: &DeserializeArgs<SP>) -> Result<Value, MaybeAttributableError<SenderError>>
);

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum ScalarFunction<SP: SessionParameters> {
    Unattributable(UnattributableScalarFunction<SP>),
    UnattributableOptional(UnattributableOptionalScalarFunction<SP>),
    UnattributableWithRng(UnattributableScalarFunctionWithRng<SP>),
}

impl<SP: SessionParameters> ScalarFunction<SP> {
    pub fn is_reproducible(&self) -> bool {
        !matches!(self, Self::UnattributableWithRng(_))
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum SimpleMappingFunction<SP: SessionParameters> {
    Unattributable(UnattributableMappingFunction<SP>),
    UnattributableWithRng(UnattributableMappingFunctionWithRng<SP>),
    SenderAttributable(SenderAttributableMappingFunction<SP>),
}

impl<SP: SessionParameters> SimpleMappingFunction<SP> {
    pub fn is_reproducible(&self) -> bool {
        !matches!(self, Self::UnattributableWithRng(_))
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub(crate) enum MappingFunction<SP: SessionParameters> {
    Unattributable(UnattributableMappingFunction<SP>),
    UnattributableWithRng(UnattributableMappingFunctionWithRng<SP>),
    SenderAttributable(SenderAttributableMappingFunction<SP>),
    SenderAttributableWithReveal(SenderAttributableWithRevealMappingFunction<SP>),
    ThirdPartyAttributable(ThirdPartyAttributableMappingFunction<SP>),
}

impl<SP: SessionParameters> From<SimpleMappingFunction<SP>> for MappingFunction<SP> {
    fn from(source: SimpleMappingFunction<SP>) -> Self {
        match source {
            SimpleMappingFunction::Unattributable(function) => Self::Unattributable(function),
            SimpleMappingFunction::UnattributableWithRng(function) => Self::UnattributableWithRng(function),
            SimpleMappingFunction::SenderAttributable(function) => Self::SenderAttributable(function),
        }
    }
}

impl<SP: SessionParameters> Display for ScalarFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::UnattributableWithRng(function) => write!(f, "{function}[RNG]"),
            Self::Unattributable(function) => write!(f, "{function}"),
            Self::UnattributableOptional(function) => write!(f, "{function}"),
        }
    }
}

impl<SP: SessionParameters> Display for SimpleMappingFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::UnattributableWithRng(function) => write!(f, "{function}[RNG]"),
            Self::Unattributable(function) => write!(f, "{function}"),
            Self::SenderAttributable(function) => write!(f, "{function}"),
        }
    }
}

impl<SP: SessionParameters> Display for MappingFunction<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::UnattributableWithRng(function) => write!(f, "{function}[RNG]"),
            Self::Unattributable(function) => write!(f, "{function}"),
            Self::SenderAttributable(function) => write!(f, "{function}"),
            Self::SenderAttributableWithReveal(function) => write!(f, "{function}"),
            Self::ThirdPartyAttributable(function) => write!(f, "{function}"),
        }
    }
}
