use alloc::{format, vec::Vec};

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{GenericArray014, Hex};
use signature::{
    DigestVerifier, Keypair, RandomizedDigestSigner,
    digest::{self, Digest},
    rand_core::CryptoRngCore,
};

use super::session_id::SessionId;
use crate::{
    error::LocalError,
    protocol::{FullName, SerializedValue, SessionParameters, WireFormat},
};

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
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

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
pub struct SignedValue<SP: SessionParameters> {
    signature: SP::Signature,
    // TODO: could be a part of the metadata and thus signed too,
    // but I don't think we get any additional security from it.
    source: SP::Verifier,
    metadata: ValueMetadata<SP>,
    value: SerializedValue,
}

impl<SP: SessionParameters> SignedValue<SP> {
    pub(crate) fn new(
        rng: &mut impl CryptoRngCore,
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
        let signature = signer
            .try_sign_digest_with_rng(rng, digest)
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

    pub fn verify(self) -> Result<VerifiedValue<SP>, VerificationError> {
        self.verify_inner()?;
        Ok(VerifiedValue {
            signature: self.signature,
            source: self.source,
            metadata: self.metadata,
            value: self.value,
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
}

impl<SP: SessionParameters> VerifiedValue<SP> {
    pub fn source(&self) -> &SP::Verifier {
        &self.source
    }

    pub fn metadata(&self) -> &ValueMetadata<SP> {
        &self.metadata
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

    pub(crate) fn sources(&self) -> impl Iterator<Item = &SP::Verifier> {
        self.values.iter().map(|value| value.source())
    }

    pub(crate) fn values(self) -> impl Iterator<Item = SignedValue<SP>> {
        self.values.into_iter()
    }
}

pub type MessageId = u64;

/*
Received message lifecycle:

[unattr] Check the signature correctness
[de facto unattr] Check that the sender is one of the paricipants
[unattr] Check that the destination is one of those managed by the session

[attr] Check session_id
[attr] Check that the name is expected
[attr] Check that the sender is in expected senders for the name
[attr]   (and the destination is in expected receivers for the name)
Check that the value with that name has not been received from that sender yet
[attr] ... it's a different value
[unattr] ... it's the same value
[attr] Check that the value can be deserialized



*/
