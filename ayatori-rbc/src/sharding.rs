//! Sharding API for arbitrary serializable types.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format, vec,
    vec::Vec,
};

use ayatori::protocol_author_api::{RuntimeError, SessionParameters, WireFormat};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};

fn usize_from_u32(x: u32) -> usize {
    usize::try_from(x).expect("`usize` is at least 4 bytes as ensured by a crate-wide assertion")
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct WireScheme {
    original_shards: u32,
    recovery_shards: u32,
    shard_size: u32,
    padding: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "WireScheme")]
#[serde(into = "WireScheme")]
pub(crate) struct Scheme {
    pub original_shards: usize,
    pub recovery_shards: usize,
    pub shard_size: usize,
    pub padding: usize,
}

impl From<Scheme> for WireScheme {
    fn from(source: Scheme) -> Self {
        // The invariants are enforced by the constructor
        Self {
            original_shards: source
                .original_shards
                .try_into()
                .expect("`original_shards` is within `u32` range"),
            recovery_shards: source
                .recovery_shards
                .try_into()
                .expect("`recovery_shards` is within `u32` range"),
            shard_size: source
                .shard_size
                .try_into()
                .expect("`shard_size` is within `u32` range"),
            padding: source.padding.try_into().expect("`padding` is within `u32` range"),
        }
    }
}

impl TryFrom<WireScheme> for Scheme {
    type Error = RuntimeError;
    fn try_from(source: WireScheme) -> Result<Self, Self::Error> {
        Self::new_inner(
            usize_from_u32(source.original_shards),
            usize_from_u32(source.recovery_shards),
            usize_from_u32(source.shard_size),
            usize_from_u32(source.padding),
        )
    }
}

impl Scheme {
    fn new(original_size: usize, total_shards: usize, threshold: usize) -> Result<Self, RuntimeError> {
        if threshold == 0 {
            return Err(RuntimeError::new("`threshold` must be non-zero"));
        }

        let shard_size = original_size.div_ceil(threshold);

        // `reed_solomon_simd` requires the shard size to be even
        let shard_size = if shard_size & 1 == 0 {
            shard_size
        } else {
            shard_size
                .checked_add(1)
                .ok_or_else(|| RuntimeError::new("The resulting shard size is too large"))?
        };

        let padded_size = shard_size
            .checked_mul(threshold)
            .ok_or_else(|| RuntimeError::new("The resulting padded size is too large"))?;
        let padding = padded_size
            .checked_sub(original_size)
            .expect("will not underflow by construction");
        let recovery_shards = total_shards
            .checked_sub(threshold)
            .ok_or_else(|| RuntimeError::new("`threshold` must not be greater than the total number of shards"))?;

        Self::new_inner(threshold, recovery_shards, shard_size, padding)
    }

    fn new_inner(
        original_shards: usize,
        recovery_shards: usize,
        shard_size: usize,
        padding: usize,
    ) -> Result<Self, RuntimeError> {
        if original_shards == 0 {
            return Err(RuntimeError::new("`original_shards` must be non-zero"));
        }

        if shard_size & 1 == 1 {
            return Err(RuntimeError::new("Shard size must be even"));
        }

        let padded_size = original_shards
            .checked_mul(shard_size)
            .ok_or_else(|| RuntimeError::new("Overflow when calculating the size of the padded message"))?;
        if padded_size <= padding {
            return Err(RuntimeError::new(
                "Padding must be smaller than the total size of the original data",
            ));
        }
        Ok(Self {
            original_shards,
            recovery_shards,
            shard_size,
            padding,
        })
    }

    fn padded_size(&self) -> usize {
        self.original_shards
            .checked_mul(self.shard_size)
            .expect("will not overflow as asserted in `new_inner()`")
    }

    fn original_size(&self) -> usize {
        self.padded_size()
            .checked_sub(self.padding)
            .expect("will not undeflow as asserted in `new_inner()`")
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum ShardKind {
    Original,
    Recovery,
}

struct OriginalShard {
    idx: usize,
    data: Box<[u8]>,
}

struct ShardRef<'a> {
    data: &'a [u8],
    idx: usize,
    kind: ShardKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WireShard {
    #[serde(with = "SliceLike::<Hex>")]
    data: Box<[u8]>,
    kind: ShardKind,
    idx: u32,
}

impl From<WireShard> for Shard {
    fn from(source: WireShard) -> Self {
        Self::new_inner(usize_from_u32(source.idx), source.kind, source.data)
    }
}

impl From<Shard> for WireShard {
    fn from(source: Shard) -> Self {
        Self {
            data: source.data,
            kind: source.kind,
            // Bounds enforced by the `Shard` constructor
            idx: u32::try_from(source.idx).expect("`idx` is within `u32` range"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "WireShard")]
#[serde(into = "WireShard")]
pub(crate) struct Shard {
    data: Box<[u8]>,
    kind: ShardKind,
    idx: usize,
}

impl Shard {
    fn new_inner(idx: usize, kind: ShardKind, data: Box<[u8]>) -> Self {
        Self { data, kind, idx }
    }

    fn new(idx: usize, kind: ShardKind, data: Box<[u8]>) -> Result<Self, RuntimeError> {
        if u32::try_from(idx).is_err() {
            return Err(RuntimeError::new("`idx` must be within `usize` bounds"));
        }
        Ok(Self::new_inner(idx, kind, data))
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    fn as_ref(&self) -> ShardRef<'_> {
        ShardRef {
            idx: self.idx,
            kind: self.kind,
            data: &self.data,
        }
    }
}

struct Decoded(Vec<OriginalShard>);

impl Decoded {
    fn new<'a>(scheme: Scheme, shards: impl Iterator<Item = ShardRef<'a>>) -> Result<Self, RuntimeError> {
        let mut decoder = ReedSolomonDecoder::new(scheme.original_shards, scheme.recovery_shards, scheme.shard_size)
            .map_err(|err| RuntimeError::new(format!("Failed to create a R-S decoded: {err}")))?;
        let mut originals = BTreeMap::new();

        for shard in shards {
            match shard.kind {
                ShardKind::Original => {
                    decoder
                        .add_original_shard(shard.idx, shard.data)
                        .map_err(|err| RuntimeError::new(format!("Failed to add an original shard: {err}")))?;
                    originals.insert(
                        shard.idx,
                        OriginalShard {
                            idx: shard.idx,
                            data: shard.data.into(),
                        },
                    );
                }
                ShardKind::Recovery => {
                    decoder
                        .add_recovery_shard(shard.idx, shard.data)
                        .map_err(|err| RuntimeError::new(format!("Failed to add a recovery shard: {err}")))?;
                }
            }
        }

        let result = decoder
            .decode()
            .map_err(|err| RuntimeError::new(format!("Failed to decode: {err}")))?;

        for (idx, data) in result.restored_original_iter() {
            originals.insert(idx, OriginalShard { idx, data: data.into() });
        }

        // At this point all the originals are accounted for, so we can dispense with the map.
        let mut originals_vec = Vec::with_capacity(originals.len());

        // BTreeMap is expected to emit elements in the order of ascending keys
        for (expected_idx, shard) in originals {
            if shard.idx != expected_idx {
                return Err(RuntimeError::new("Unexpected order of returned shards"));
            }
            originals_vec.push(shard);
        }

        Ok(Self(originals_vec))
    }

    fn into_shards(self) -> Vec<OriginalShard> {
        self.0
    }
}

struct Encoded(Vec<Shard>);

impl Encoded {
    fn new_inner<'a>(scheme: Scheme, originals: impl Iterator<Item = (usize, &'a [u8])>) -> Result<Self, RuntimeError> {
        let mut encoder = ReedSolomonEncoder::new(scheme.original_shards, scheme.recovery_shards, scheme.shard_size)
            .map_err(|err| RuntimeError::new(format!("Failed to create a R-S encoder: {err}")))?;
        let mut shards = Vec::new();

        for (idx, data) in originals {
            encoder
                .add_original_shard(data)
                .map_err(|err| RuntimeError::new(format!("Failed to add an original shard: {err}")))?;
            shards.push(Shard::new(idx, ShardKind::Original, data.into())?);
        }

        let result = encoder
            .encode()
            .map_err(|err| RuntimeError::new(format!("Failed to encode: {err}")))?;

        for (idx, data) in result.recovery_iter().enumerate() {
            shards.push(Shard::new(idx, ShardKind::Recovery, data.into())?);
        }

        Ok(Self(shards))
    }

    fn new<'a>(scheme: Scheme, originals: impl Iterator<Item = &'a [u8]>) -> Result<Self, RuntimeError> {
        Self::new_inner(scheme, originals.enumerate())
    }

    fn from_decoded(scheme: Scheme, decoded: &Decoded) -> Result<Self, RuntimeError> {
        Self::new_inner(scheme, decoded.0.iter().map(|shard| shard.data.as_ref()).enumerate())
    }

    fn into_shards(self) -> Vec<Shard> {
        self.0
    }
}

// TODO: do we need to match shards with IDs here, or can it be done a level above?
pub(crate) fn new_set<SP: SessionParameters, T: Serialize>(
    value: &T,
    threshold: usize,
    ids: &BTreeSet<SP::Verifier>,
) -> Result<(Scheme, BTreeMap<SP::Verifier, Shard>), RuntimeError> {
    let mut serialized = SP::WireFormat::serialize(value)?.into_vec();

    let scheme = Scheme::new(serialized.len(), ids.len(), threshold)?;

    serialized.resize(scheme.padded_size(), 0);

    let encoded = Encoded::new(scheme, serialized.chunks(scheme.shard_size))?;

    let mut shards = BTreeMap::new();
    for (id, shard) in ids.iter().zip(encoded.into_shards()) {
        shards.insert(id.clone(), shard);
    }

    Ok((scheme, shards))
}

pub(crate) fn interpolate<'a, SP: SessionParameters>(
    scheme: Scheme,
    shards: impl Iterator<Item = &'a Shard>,
    ids: &BTreeSet<SP::Verifier>,
) -> Result<BTreeMap<SP::Verifier, Shard>, RuntimeError> {
    let decoded = Decoded::new(scheme, shards.map(|shard| shard.as_ref()))?;
    let encoded = Encoded::from_decoded(scheme, &decoded)?;

    let mut shards = BTreeMap::new();
    for (id, shard) in ids.iter().zip(encoded.into_shards()) {
        shards.insert(id.clone(), shard);
    }

    Ok(shards)
}

pub(crate) fn assemble<'a, SP: SessionParameters, T: for<'de> Deserialize<'de>>(
    scheme: Scheme,
    shards: impl Iterator<Item = &'a Shard>,
) -> Result<T, RuntimeError> {
    let decoded = Decoded::new(scheme, shards.map(|shard| shard.as_ref()))?;

    let mut original_data = vec![0; scheme.padded_size()];

    for (chunk, shard) in original_data
        .chunks_exact_mut(scheme.shard_size)
        .zip(decoded.into_shards())
    {
        chunk.copy_from_slice(&shard.data);
    }

    original_data.truncate(scheme.original_size());

    SP::WireFormat::deserialize::<T>(&original_data)
        .map_err(|err| RuntimeError::new(format!("Failed to deserialize: {err}")))
}

#[cfg(test)]
#[expect(clippy::indexing_slicing)]
mod tests {
    use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};

    use ayatori::dev::{BinaryFormat, TestSessionParams, TestVerifier};
    use rand_chacha::ChaCha8Rng;
    use serde::{Deserialize, Serialize};
    use serde_encoded_bytes::{Hex, SliceLike};

    use super::{assemble, interpolate, new_set};

    type SP = TestSessionParams<BinaryFormat, ChaCha8Rng>;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct Value {
        x: u64,
        #[serde(with = "SliceLike::<Hex>")]
        y: Box<[u8]>,
        z: u64,
    }

    #[test]
    fn create_shards() {
        let value = Value {
            x: 123,
            y: b"just a test string nothing special".to_vec().into_boxed_slice(),
            z: 456,
        };

        let threshold = 3;
        let shards_num = 5;

        let ids = (0..shards_num).map(TestVerifier::new).collect::<Vec<_>>();
        let ids_set = ids.iter().copied().collect::<BTreeSet<_>>();
        let (scheme, shards) = new_set::<SP, _>(&value, threshold, &ids_set).unwrap();

        let some_shards = [
            shards[&ids[0]].clone(),
            shards[&ids[2]].clone(),
            shards[&ids[4]].clone(),
        ];
        let value_back = assemble::<SP, Value>(scheme, some_shards.iter()).unwrap();

        assert_eq!(value, value_back);
    }

    #[test]
    fn interpolate_shards() {
        let value = Value {
            x: 123,
            y: b"just a test string nothing special".to_vec().into_boxed_slice(),
            z: 456,
        };

        let threshold = 3;
        let shards_num = 5;

        let ids = (0..shards_num).map(TestVerifier::new).collect::<Vec<_>>();
        let ids_set = ids.iter().copied().collect::<BTreeSet<_>>();
        let (scheme, shards) = new_set::<SP, _>(&value, threshold, &ids_set).unwrap();

        let some_shards = [
            shards[&ids[0]].clone(),
            shards[&ids[2]].clone(),
            shards[&ids[4]].clone(),
        ];
        let interpolated = interpolate::<SP>(scheme, some_shards.iter(), &ids_set).unwrap();

        assert_eq!(shards, interpolated);
    }
}
