use alloc::boxed::Box;
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use signature::{DigestVerifier, Keypair, RandomizedDigestSigner, digest::Digest};

use super::{node::Node, value::Erasable};
use crate::error::LocalError;

pub trait PartyId:
    'static + Debug + Clone + PartialEq + Eq + PartialOrd + Ord + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
}

impl<T> PartyId for T where
    T: 'static
        + Debug
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Send
        + Sync
        + Serialize
        + for<'de> Deserialize<'de>
{
}

/// A (de)serializer that will be used for the protocol messages.
pub trait WireFormat: 'static + Debug {
    /// Serializes the given object into a bytestring.
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError>;

    type DeError: serde::de::Error;

    fn deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Self::DeError>;
}

pub trait SessionParameters: 'static {
    type Signer: Debug + RandomizedDigestSigner<Self::Digest, Self::Signature> + Keypair<VerifyingKey = Self::Verifier>;

    type Digest: Digest;

    type Verifier: PartyId + DigestVerifier<Self::Digest, Self::Signature> + Serialize + for<'de> Deserialize<'de>;

    type Signature: Send + Sync + Debug + Clone + Serialize + for<'de> Deserialize<'de>;

    type WireFormat: WireFormat;
}

pub trait Protocol<SP: SessionParameters>: Sized + Debug {
    type BuildData;
    type SharedData: Erasable;
    // TODO: we may not need `Clone` here
    type Output: 'static + Clone + Erasable;

    fn build(my_id: &SP::Verifier, build_data: &Self::BuildData) -> Result<Node<SP>, LocalError>;
}
