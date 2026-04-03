use alloc::{format, vec::Vec};
use core::fmt::{self, Debug};

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{GenericArray014, Hex};
use signature::{
    DigestVerifier, Keypair, RandomizedDigestSigner,
    digest::{self, Digest},
    rand_core::CryptoRngCore,
};

use super::{session_id::SessionId, tag::FullName, value::SerializedValue};
use crate::{
    errors::LocalError,
    traits::{SessionParameters, WireFormat},
};

#[derive_where::derive_where(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueMetadata<SP: SessionParameters> {
    name: FullName,
    destination: SP::Verifier,
    session_id: SessionId<SP>,
}

impl<SP: SessionParameters> ValueMetadata<SP> {
    pub fn full_name(&self) -> &FullName {
        &self.name
    }

    pub fn destination(&self) -> &SP::Verifier {
        &self.destination
    }

    pub fn session_id(&self) -> &SessionId<SP> {
        &self.session_id
    }
}

#[derive(Debug, Clone)]
pub enum VerificationError {
    Local(LocalError),
    SignatureMismatch,
}

impl From<LocalError> for VerificationError {
    fn from(source: LocalError) -> Self {
        Self::Local(source)
    }
}

fn hash_serialized_value<D: Digest>(value: &SerializedValue) -> Result<digest::Output<D>, LocalError> {
    let value_len =
        u64::try_from(value.as_ref().len()).map_err(|_| LocalError::new("Message size exceeds 2^64 bytes"))?;
    Ok(D::new_with_prefix(b"SerializedValueDigest")
        .chain_update(value_len.to_be_bytes())
        .chain_update(value.as_ref())
        .finalize())
}

fn hash_value_hash_and_metadata<SP: SessionParameters>(
    value_hash: &digest::Output<SP::Digest>,
    metadata: &ValueMetadata<SP>,
) -> Result<SP::Digest, LocalError> {
    Ok(SP::Digest::new_with_prefix(b"SignedValueDigest")
        .chain_update(<SP::WireFormat as WireFormat>::serialize(metadata)?)
        .chain_update(value_hash.as_ref()))
}

fn hash_value_and_metadata<SP: SessionParameters>(
    value: &SerializedValue,
    metadata: &ValueMetadata<SP>,
) -> Result<SP::Digest, LocalError> {
    let value_hash = hash_serialized_value::<SP::Digest>(value)?;
    hash_value_hash_and_metadata::<SP>(&value_hash, metadata)
}

/// A wrapper to convert `dyn CryptoRngCore` to a sized `impl CryptoRngCore`,
/// since some RustCrypto libraries don't accept a `?Sized` RNG.
struct Rng<'a>(&'a mut dyn CryptoRngCore);

impl signature::rand_core::RngCore for Rng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.fill_bytes(bytes);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), signature::rand_core::Error> {
        self.0.try_fill_bytes(bytes)
    }
}

impl signature::rand_core::CryptoRng for Rng<'_> {}

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
pub struct SignedValue<SP: SessionParameters> {
    signature: SP::Signature,
    source: SP::Verifier,
    metadata: ValueMetadata<SP>,
    value: SerializedValue,
}

impl<SP: SessionParameters> SignedValue<SP> {
    pub(crate) fn new(
        rng: &mut dyn CryptoRngCore,
        signer: &SP::Signer,
        session_id: &SessionId<SP>,
        name: &FullName,
        destination: &SP::Verifier,
        value: SerializedValue,
    ) -> Result<Self, LocalError> {
        let metadata = ValueMetadata {
            name: name.clone(),
            destination: destination.clone(),
            session_id: session_id.clone(),
        };
        let digest = hash_value_and_metadata::<SP>(&value, &metadata)?;
        let mut typed_rng = Rng(rng);
        let signature = signer
            .try_sign_digest_with_rng(&mut typed_rng, digest)
            .map_err(|err| LocalError::new(format!("Signing failed: {err}")))?;
        Ok(Self {
            signature,
            source: signer.verifying_key(),
            metadata,
            value,
        })
    }

    pub fn source(&self) -> &SP::Verifier {
        &self.source
    }

    fn verify_inner(&self) -> Result<(), VerificationError> {
        let digest = hash_value_and_metadata::<SP>(&self.value, &self.metadata)?;
        self.source
            .verify_digest(digest, &self.signature)
            .map_err(|_err| VerificationError::SignatureMismatch)
    }

    pub fn is_signature_correct(&self) -> bool {
        self.verify_inner().is_ok()
    }

    pub(crate) fn verify_and_unpack(self) -> Result<SerializedValue, VerificationError> {
        self.verify_inner()?;
        Ok(self.value)
    }

    pub fn verify(self, message_id: &MessageId<SP>) -> Result<VerifiedValue<SP>, VerificationError> {
        self.verify_inner()?;
        Ok(VerifiedValue {
            signature: self.signature,
            source: self.source,
            metadata: self.metadata,
            value: self.value,
            message_id: message_id.clone(),
        })
    }

    pub fn metadata(&self) -> &ValueMetadata<SP> {
        &self.metadata
    }
}

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHash<SP: SessionParameters> {
    signature: SP::Signature,
    source: SP::Verifier,
    metadata: ValueMetadata<SP>,
    #[serde(with = "GenericArray014::<Hex>")]
    hash: digest::Output<SP::Digest>,
}

impl<SP: SessionParameters> SignedHash<SP> {
    pub fn source(&self) -> &SP::Verifier {
        &self.source
    }

    pub fn metadata(&self) -> &ValueMetadata<SP> {
        &self.metadata
    }

    fn verify_inner(&self) -> Result<(), VerificationError> {
        let digest = hash_value_hash_and_metadata::<SP>(&self.hash, &self.metadata)?;
        self.source
            .verify_digest(digest, &self.signature)
            .map_err(|_err| VerificationError::SignatureMismatch)
    }

    pub fn is_signature_correct(&self) -> bool {
        self.verify_inner().is_ok()
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub struct VerifiedValue<SP: SessionParameters> {
    signature: SP::Signature,
    source: SP::Verifier,
    metadata: ValueMetadata<SP>,
    value: SerializedValue,
    message_id: MessageId<SP>,
}

impl<SP: SessionParameters> VerifiedValue<SP> {
    pub fn source(&self) -> &SP::Verifier {
        &self.source
    }

    pub fn metadata(&self) -> &ValueMetadata<SP> {
        &self.metadata
    }

    pub(crate) fn message_id(&self) -> &MessageId<SP> {
        &self.message_id
    }

    pub(crate) fn serialized_value(&self) -> &SerializedValue {
        &self.value
    }

    pub fn payload_hash_matches(&self, other: &SignedHash<SP>) -> Result<bool, LocalError> {
        let value_hash = hash_serialized_value::<SP::Digest>(&self.value)?;
        Ok(value_hash.as_ref() == other.hash.as_ref())
    }

    pub fn unverify(self) -> SignedValue<SP> {
        SignedValue {
            signature: self.signature,
            source: self.source,
            metadata: self.metadata,
            value: self.value,
        }
    }

    pub fn to_signed_hash(&self) -> Result<SignedHash<SP>, LocalError> {
        let value_hash = hash_serialized_value::<SP::Digest>(&self.value)?;
        Ok(SignedHash {
            signature: self.signature.clone(),
            source: self.source.clone(),
            metadata: self.metadata.clone(),
            hash: value_hash,
        })
    }
}

/// An ID associated with an incoming [`Message`](`crate::protocol_user_api::Message`).
///
/// The user is expected to generate and store the ID in association with the message source
/// (the nature of which will depend on the transport channel used).
/// If there is a problem with the message that cannot be associated with the specific verifier,
/// the returned error will contain the ID of the message the information came from.
/// Then, the user can use whatever measures necessary towards the associated source.
#[derive(Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[derive_where::derive_where(Clone, PartialEq, Eq)]
pub struct MessageId<SP: SessionParameters>(#[serde(with = "GenericArray014::<Hex>")] digest::Output<SP::Digest>);

impl<SP: SessionParameters> MessageId<SP> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut buffer = digest::Output::<SP::Digest>::default();
        rng.fill_bytes(&mut buffer);
        Self(buffer)
    }

    pub(crate) fn from_usize(id: usize) -> Self {
        Self(SP::Digest::new().chain_update(id.to_be_bytes()).finalize())
    }
}

impl<SP: SessionParameters> Debug for MessageId<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "MessageId({})", hex::encode(self.0.as_ref()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message<SP: SessionParameters> {
    destination: SP::Verifier,
    values: Vec<SignedValue<SP>>,
}

impl<SP: SessionParameters> Message<SP> {
    pub(crate) fn new(destination: SP::Verifier, values: Vec<SignedValue<SP>>) -> Self {
        Self { destination, values }
    }

    pub fn destination(&self) -> &SP::Verifier {
        &self.destination
    }

    pub(crate) fn into_values(self) -> impl Iterator<Item = SignedValue<SP>> {
        self.values.into_iter()
    }
}
