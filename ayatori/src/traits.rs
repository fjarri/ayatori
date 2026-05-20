use alloc::{boxed::Box, collections::BTreeSet};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use signature::{DigestVerifier, Keypair, RandomizedDigestSigner, digest::FixedOutput, rand_core::TryCryptoRng};

use crate::{
    entities::{Erasable, RuntimeError},
    graph_representation::{
        AnyNode, ArgNodes, OutputNode, PartyBuildData, PrivateInputs, ProtocolSignature, PublicInputs,
    },
};

#[cfg(doc)]
use crate::{protocol_author_api::call_protocol, protocol_user_api::Session};

/// An ID of a protocol participant.
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
pub trait WireFormat: 'static {
    /// Serializes the given object into a bytestring.
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, RuntimeError>;

    /// A possible deserialization error (format-specific).
    type DeError: serde::de::Error;

    /// Deserializes an object from the given bytestring.
    fn deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Self::DeError>;
}

/// A set of types needed to execute a session.
///
/// These will be generally determined by the user, depending on what signature type
/// is used in the network in which they are running the protocol, and security requirements.
pub trait SessionParameters: 'static {
    /// The signer type.
    type Signer: Debug + RandomizedDigestSigner<Self::Digest, Self::Signature> + Keypair<VerifyingKey = Self::Verifier>;

    /// The hash type that will be used to pre-hash message payloads before signing.
    type Digest: FixedOutput + Default;

    /// The verifier type, which will also serve as a party identifier.
    type Verifier: PartyId + DigestVerifier<Self::Digest, Self::Signature> + Serialize + for<'de> Deserialize<'de>;

    /// The signature type corresponding to [`Signer`](`Self::Signer`) and [`Verifier`](`Self::Verifier`).
    type Signature: Send + Sync + Debug + Clone + Serialize + for<'de> Deserialize<'de>;

    /// The RNG used by the session computations.
    type Rng: TryCryptoRng;

    /// The type used to (de)serialize messages.
    type WireFormat: WireFormat;
}

/// Defines a protocol executable by a [`Session`].
pub trait ExecutableProtocol<SP: SessionParameters>: ComposableProtocol<SP, OutputNode: Into<OutputNode<SP>>> {
    /// Public data shared by all the participants.
    type SharedData;

    /// Private party-specific data.
    type PrivateData;

    /// Protocol output.
    // The `Clone` bound is necessary to downcast the erased value to a typed one when the session is ready to finalize;
    // we cannot guarantee that there is only one reference to it at that point.
    type Output: Clone + Erasable;

    /// Decomposes the shared data object into public inputs to the protocol.
    fn make_public_inputs(shared_data: &Self::SharedData) -> PublicInputs;

    /// Decomposes the private data object into private inputs to the protocol.
    fn make_private_inputs(private_data: &Self::PrivateData) -> PrivateInputs;

    /// Reduces the shared data object to the data available at graph build time.
    fn make_build_data(shared_data: &Self::SharedData) -> <Self as ComposableProtocol<SP>>::BuildData;

    /// Returns the set of all participants of the protocol.
    fn all_participants(shared_data: &Self::SharedData) -> BTreeSet<SP::Verifier>;
}

/// Defines a protocol that can be called as a subprotocol via [`call_protocol`].
pub trait ComposableProtocol<SP: SessionParameters>: 'static {
    /// Public shared data available at graph build time.
    type BuildData;

    /// The type of the output node of the protocol.
    type OutputNode: Into<AnyNode<SP>> + TryFrom<AnyNode<SP>>;

    /// Declares the protocol signature.
    fn signature() -> ProtocolSignature;

    /// Builds the protocol graph.
    fn build(
        party_build_data: &PartyBuildData<SP>,
        build_data: &Self::BuildData,
        inputs: ArgNodes<SP>,
    ) -> Result<Self::OutputNode, RuntimeError>;
}
