use alloc::{boxed::Box, string::ToString};

use serde::{Deserialize, Serialize};

use crate::{error::LocalError, protocol::WireFormat};

/// A binary format to use in tests.
#[derive(Debug, Clone, Copy)]
pub struct BinaryFormat;

impl WireFormat for BinaryFormat {
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError> {
        postcard::to_allocvec(&value)
            .map(Into::into)
            .map_err(|err| LocalError::new(err.to_string()))
    }

    type DeError = postcard::Error;

    fn deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Self::DeError> {
        postcard::from_bytes(bytes)
    }
}

/// A human-readable format to use in tests.
#[derive(Debug, Clone, Copy)]
pub struct HumanReadableFormat;

impl WireFormat for HumanReadableFormat {
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError> {
        serde_json::to_vec(&value)
            .map(Into::into)
            .map_err(|err| LocalError::new(err.to_string()))
    }

    type DeError = serde_json::Error;

    fn deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Self::DeError> {
        serde_json::from_slice(bytes)
    }
}
