use alloc::{boxed::Box, format, string::String, sync::Arc};
use core::{
    any::{Any, TypeId, type_name},
    fmt::{self, Debug},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};

use super::traits::WireFormat;

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

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn debug(&self) -> String {
        format!("{:?}", self)
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

    fn downcast_arc<T>(&self) -> Option<Arc<T>>
    where
        T: Erasable,
    {
        // This is essentially `Arc::downcast()`, but since we cannot use the internal methods it uses,
        // we rely on `into_raw()`/`from_raw()` instead.

        if self.0.as_ref().my_type_id() != TypeId::of::<T>() {
            return None;
        }

        // Increase the refcount first so that the `Arc`-wrapped value doesn't get dropped
        // as we go through the logic.
        let arc = self.0.clone();

        let raw = Arc::into_raw(arc) as *const T;

        // SAFETY:
        // - `TypeId` was checked
        // - `raw` points to the original `Arc` allocation
        // - `from_raw` restores correct refcount
        // - The object will not get dropped since we created an additional reference beforehand.
        let typed_arc = unsafe { Arc::from_raw(raw) };

        Some(typed_arc)
    }

    pub fn downcast<T: Erasable + Clone>(&self) -> T {
        let dc = self.downcast_arc::<T>().unwrap();
        Arc::unwrap_or_clone(dc)
    }

    pub fn downcast_ref<T: Erasable>(&self) -> &T {
        // Note that `as_ref()` here is crucial, otherwise `as_any()`
        // is called on the `Arc` instead of the concrete type inside,
        // leading to `downcast_ref()` failing because of the type mismatch.
        self.0.as_ref().as_any().downcast_ref::<T>().unwrap()
    }
}

trait DynAdapter {
    fn as_serialize<'a>(&'a self, value: &'a Value) -> &'a dyn erased_serde::Serialize;
    fn deserialize(&self, deserializer: &mut dyn erased_serde::Deserializer<'_>) -> Value;
    fn clone_boxed(&self) -> Box<dyn DynAdapter>;
    fn debug(&self) -> String;
}

impl<T: Erasable + Serialize + for<'de> Deserialize<'de>> DynAdapter for DynAdapterHolder<T> {
    fn as_serialize<'a>(&'a self, value: &'a Value) -> &'a dyn erased_serde::Serialize {
        value.downcast_ref::<T>()
    }

    fn deserialize(&self, deserializer: &mut dyn erased_serde::Deserializer<'_>) -> Value {
        let typed_value = erased_serde::deserialize::<T>(deserializer).unwrap();
        Value::new(typed_value)
    }

    fn clone_boxed(&self) -> Box<dyn DynAdapter> {
        Box::new(DynAdapterHolder::<T>(PhantomData))
    }

    fn debug(&self) -> String {
        format!("<{}>", type_name::<T>())
    }
}

struct DynAdapterHolder<T>(PhantomData<T>);

pub(crate) struct SerdeAdapter(Box<dyn DynAdapter>);

impl SerdeAdapter {
    pub fn new<T: Erasable + Serialize + for<'de> Deserialize<'de>>() -> Self {
        Self(Box::new(DynAdapterHolder::<T>(PhantomData)))
    }

    pub fn serialize<F: WireFormat>(&self, value: &Value) -> SerializedValue {
        SerializedValue::new(F::serialize(self.0.as_serialize(value)).unwrap())
    }

    pub fn deserialize<F: WireFormat>(&self, serialized_value: &SerializedValue) -> Value {
        let deserializer = F::deserializer(serialized_value.as_ref());
        let mut erased_deserializer = Box::new(<dyn erased_serde::Deserializer<'_>>::erase(deserializer));
        self.0.deserialize(&mut erased_deserializer)
    }
}

impl Clone for SerdeAdapter {
    fn clone(&self) -> Self {
        Self(self.0.clone_boxed())
    }
}

impl Debug for SerdeAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "SerdeAdapter({})", self.0.as_ref().debug())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedValue(
    // TODO: would be nice to store it as is if the serializer is human-readable
    #[serde(with = "SliceLike::<Hex>")] Box<[u8]>,
);

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
        let integer = value.downcast::<u64>();
        assert_eq!(Arc::strong_count(&value.0), 1);
        assert_eq!(integer, typed_value);

        let integer = value.downcast_ref::<u64>();
        assert_eq!(integer, &typed_value);
    }

    #[test]
    fn serialize_roundtrip() {
        let typed_value = Serializable { x: 10, y: true };
        let value = Value::new(typed_value);
        let adapter = SerdeAdapter::new::<Serializable>();
        let serialized = adapter.serialize::<BinaryFormat>(&value);
        let value_back = adapter.deserialize::<BinaryFormat>(&serialized);
        let typed_value_back = value_back.downcast::<Serializable>();
        assert_eq!(typed_value, typed_value_back);
    }
}
