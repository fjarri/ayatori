use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
};
use core::{
    any::{Any, TypeId, type_name},
    fmt::{self, Debug},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};

use crate::{errors::LocalError, traits::WireFormat};

/*
We need a dyn trait that both supports downcast for `Arc`s (like `Any` does),
and also some additional methods.

Unfortunately in the current stable Rust we cannot do `Arc<dyn Any + MyTrait>`,
so we have to create our own trait and do manual typechecks and some `unsafe` magic.
*/

pub trait Erasable: Any + Debug + Send + Sync + 'static {}

impl<T: Any + Debug + Send + Sync + 'static> Erasable for T {}

trait ErasableInternal: Erasable {
    fn my_type_id(&self) -> TypeId;
    fn my_type_name(&self) -> String;
    fn as_any(&self) -> &dyn Any;
    fn debug(&self) -> String;
}

impl<T> ErasableInternal for T
where
    T: Any + Debug + Send + Sync + 'static,
{
    fn my_type_id(&self) -> TypeId {
        TypeId::of::<T>()
    }

    fn my_type_name(&self) -> String {
        type_name::<T>().into()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn debug(&self) -> String {
        format!("{self:?}")
    }
}

#[derive(Clone)]
pub(crate) struct Value(Arc<dyn ErasableInternal>);

impl Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Value(Arc({}))", self.0.as_ref().debug())
    }
}

impl Value {
    pub fn new<T: Erasable>(value: T) -> Self {
        Self(Arc::new(value))
    }

    fn downcast_arc<T>(&self) -> Result<Arc<T>, LocalError>
    where
        T: Erasable,
    {
        // This is essentially `Arc::downcast()`, but since we cannot use the internal methods it uses,
        // we rely on `into_raw()`/`from_raw()` instead.

        if self.0.as_ref().my_type_id() != TypeId::of::<T>() {
            return Err(LocalError::new(format!(
                "Attempted to downcast {} as {}",
                self.0.as_ref().my_type_name(),
                type_name::<T>()
            )));
        }

        // Increase the refcount first so that the `Arc`-wrapped value doesn't get dropped
        // as we go through the logic.
        let arc = self.0.clone();

        let raw = Arc::into_raw(arc).cast::<T>();

        // SAFETY:
        // - `TypeId` was checked
        // - `raw` points to the original `Arc` allocation
        // - `from_raw` restores correct refcount
        // - The object will not get dropped since we created an additional reference beforehand.
        let typed_arc = unsafe { Arc::from_raw(raw) };

        Ok(typed_arc)
    }

    pub fn downcast<T: Erasable + Clone>(&self) -> Result<T, LocalError> {
        self.downcast_arc::<T>().map(Arc::unwrap_or_clone)
    }

    pub fn downcast_ref<T: Erasable>(&self) -> Result<&T, LocalError> {
        // Note that `as_ref()` here is crucial, otherwise `as_any()`
        // is called on the `Arc` instead of the concrete type inside,
        // leading to `downcast_ref()` failing because of the type mismatch.
        self.0.as_ref().as_any().downcast_ref::<T>().ok_or_else(|| {
            LocalError::new(format!(
                "Attempted to downcast {} as {}",
                self.0.as_ref().my_type_name(),
                type_name::<T>()
            ))
        })
    }
}

/// An error that can be returned during deserialization.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Error deserializing into {target_type}: {message}")]
pub(crate) struct DeserializationError {
    target_type: String,
    message: String,
}

impl DeserializationError {
    /// Creates a new deserialization error.
    pub fn new<T>(message: impl Into<String>) -> Self {
        Self {
            target_type: type_name::<T>().into(),
            message: message.into(),
        }
    }
}

trait DynAdapter<F: WireFormat> {
    fn serialize(&self, value: &Value) -> Result<SerializedValue, LocalError>;
    fn deserialize(&self, serialized_value: &SerializedValue) -> Result<Value, DeserializationError>;
    fn clone_boxed(&self) -> Box<dyn DynAdapter<F>>;
    fn debug(&self) -> String;
}

impl<F: WireFormat, T: Erasable + Serialize + for<'de> Deserialize<'de>> DynAdapter<F> for DynAdapterHolder<F, T> {
    fn serialize(&self, value: &Value) -> Result<SerializedValue, LocalError> {
        let typed_value = value.downcast_ref::<T>()?;
        Ok(SerializedValue::new(F::serialize(typed_value)?))
    }

    fn deserialize(&self, serialized_value: &SerializedValue) -> Result<Value, DeserializationError> {
        F::deserialize::<T>(serialized_value.as_ref())
            .map(Value::new)
            .map_err(|err| DeserializationError::new::<T>(err.to_string()))
    }

    fn clone_boxed(&self) -> Box<dyn DynAdapter<F>> {
        Box::new(DynAdapterHolder::<F, T>(PhantomData))
    }

    fn debug(&self) -> String {
        format!("<{}>", type_name::<T>())
    }
}

struct DynAdapterHolder<F, T>(PhantomData<(F, T)>);

pub(crate) struct SerdeAdapter<F: WireFormat>(Box<dyn DynAdapter<F>>);

impl<F: WireFormat> SerdeAdapter<F> {
    pub fn new<T: Erasable + Serialize + for<'de> Deserialize<'de>>() -> Self {
        Self(Box::new(DynAdapterHolder::<F, T>(PhantomData)))
    }

    pub fn serialize(&self, value: &Value) -> Result<SerializedValue, LocalError> {
        self.0.serialize(value)
    }

    pub fn deserialize(&self, serialized_value: &SerializedValue) -> Result<Value, DeserializationError> {
        self.0.deserialize(serialized_value)
    }
}

impl<F: WireFormat> Clone for SerdeAdapter<F> {
    fn clone(&self) -> Self {
        Self(self.0.clone_boxed())
    }
}

impl<F: WireFormat> Debug for SerdeAdapter<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "SerdeAdapter({})", self.0.as_ref().debug())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SerializedValue(#[serde(with = "SliceLike::<Hex>")] Box<[u8]>);

impl SerializedValue {
    pub fn new(data: Box<[u8]>) -> Self {
        Self(data)
    }

    pub fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use serde::{Deserialize, Serialize};

    use super::{SerdeAdapter, Value};
    use crate::dev::BinaryFormat;

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    struct Serializable {
        x: u64,
        y: bool,
    }

    #[test]
    fn roundtrip() {
        let typed_value = 10u64;
        let value = Value::new(typed_value);
        assert_eq!(Arc::strong_count(&value.0), 1);
        let integer = value.downcast::<u64>().unwrap();
        assert_eq!(Arc::strong_count(&value.0), 1);
        assert_eq!(integer, typed_value);

        let integer = value.downcast_ref::<u64>().unwrap();
        assert_eq!(integer, &typed_value);
    }

    #[test]
    fn serialize_roundtrip() {
        let typed_value = Serializable { x: 10, y: true };
        let value = Value::new(typed_value);
        let adapter = SerdeAdapter::<BinaryFormat>::new::<Serializable>();
        let serialized = adapter.serialize(&value).unwrap();
        let value_back = adapter.deserialize(&serialized).unwrap();
        let typed_value_back = value_back.downcast::<Serializable>().unwrap();
        assert_eq!(typed_value, typed_value_back);
    }
}
