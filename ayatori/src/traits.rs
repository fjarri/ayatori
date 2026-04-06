use alloc::{boxed::Box, collections::BTreeSet};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use signature::{DigestVerifier, Keypair, RandomizedDigestSigner, digest::Digest};

use crate::{
    entities::{Erasable, RuntimeError},
    graph_representation::{
        AnyNode, ArgNodes, OutputNode, PartyBuildData, PrivateInputs, ProtocolSignature, PublicInputs,
    },
};

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
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, RuntimeError>;

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

pub trait ExecutableProtocol<SP: SessionParameters>:
    Debug + ComposableProtocol<SP, OutputNode: Into<OutputNode<SP>>>
{
    type SharedData;
    type PrivateData;
    // The `Clone` bound is necessary to downcast the erased value to a typed one when the session is ready to finalize;
    // we cannot guarantee that there is only one reference to it at that point.
    type Output: Clone + Erasable;

    fn make_public_inputs(shared_data: &Self::SharedData) -> PublicInputs;
    fn make_private_inputs(private_data: &Self::PrivateData) -> PrivateInputs;
    fn make_build_data(shared_data: &Self::SharedData) -> <Self as ComposableProtocol<SP>>::BuildData;
    fn all_participants(shared_data: &Self::SharedData) -> BTreeSet<SP::Verifier>;
}

pub trait ComposableProtocol<SP: SessionParameters>: Debug {
    type BuildData;
    type OutputNode: Into<AnyNode<SP>> + TryFrom<AnyNode<SP>>;

    fn signature() -> ProtocolSignature;

    fn build(
        party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        inputs: ArgNodes,
    ) -> Result<Self::OutputNode, RuntimeError>;
}
