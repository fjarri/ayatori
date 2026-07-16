use alloc::{boxed::Box, string::ToString};

use serde::{Deserialize, Serialize, de::Error as _};

use crate::{entities::RuntimeError, traits::WireFormat};

/// A binary format to use in tests.
#[derive(Debug, Clone, Copy)]
pub struct BinaryFormat;

impl WireFormat for BinaryFormat {
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, RuntimeError> {
        postcard::to_allocvec(&value)
            .map(Into::into)
            .map_err(|err| RuntimeError::new(err.to_string()))
    }

    type DeError = postcard::Error;

    fn deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Self::DeError> {
        let (result, unused_bytes) = postcard::take_from_bytes(bytes)?;
        if !unused_bytes.is_empty() {
            return Err(postcard::Error::custom("Unused data left after deserialization"));
        }
        Ok(result)
    }
}

/// A human-readable format to use in tests.
#[derive(Debug, Clone, Copy)]
pub struct HumanReadableFormat;

impl WireFormat for HumanReadableFormat {
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, RuntimeError> {
        serde_json::to_vec(&value)
            .map(Into::into)
            .map_err(|err| RuntimeError::new(err.to_string()))
    }

    type DeError = serde_json::Error;

    fn deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Self::DeError> {
        serde_json::from_slice(bytes)
    }
}
