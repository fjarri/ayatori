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

/*
Why the asymmetry between serialization and deserialization?

If we had a method returning an object of a type implementing `serde::Serializer`,
we could organize the serialization in the same way as deserialization.
But libraries generally expose `T where &mut T: Serializer`,
and it's tricky to write a similar persistent wrapper as we do for the deserializer
(see https://github.com/fjarri/serde-persistent-deserializer/issues/2).

So for serialization we have to instead type-erase the value itself and pass it somewhere
where the serializer type is known (see `SerdeAdapter::serialize()`);
but for the deserialization we instead type-erase the deserializer and pass it somewhere
the type of the target value is known (see `SerdeAdapter::deserialize()`).
*/

/// A (de)serializer that will be used for the protocol messages.
pub trait WireFormat: 'static + Debug {
    /// Serializes the given object into a bytestring.
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError>;

    /// The deserializer type.
    type Deserializer<'de>: serde::Deserializer<'de>;

    /// Creates a `serde` deserializer given a bytestring.
    fn deserializer(bytes: &[u8]) -> Self::Deserializer<'_>;
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

    fn build(
        my_id: &SP::Verifier,
        build_data: &Self::BuildData,
        shared_data: &Node<SP>,
    ) -> Result<Node<SP>, LocalError>;
}
