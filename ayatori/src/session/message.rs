use alloc::{format, vec::Vec};

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{GenericArray014, Hex};
use signature::{
    DigestVerifier, Keypair, RandomizedDigestSigner,
    digest::{self, Digest},
    rand_core::CryptoRngCore,
};

use crate::{
    error::LocalError,
    protocol::{FullName, SerializedValue, SessionParameters, WireFormat},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueMetadata<Id> {
    name: FullName,
    destination: Id,
}

impl<Id> ValueMetadata<Id> {
    pub fn full_name(&self) -> &FullName {
        &self.name
    }

    pub fn destination(&self) -> &Id {
        &self.destination
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
    metadata: &ValueMetadata<SP::Verifier>,
) -> Result<SP::Digest, LocalError> {
    Ok(SP::Digest::new_with_prefix(b"SignedValueDigest")
        .chain_update(<SP::WireFormat as WireFormat>::serialize(metadata)?)
        .chain_update(value_hash.as_ref()))
}

fn hash_value_and_metadata<SP: SessionParameters>(
    value: &SerializedValue,
    metadata: &ValueMetadata<SP::Verifier>,
) -> Result<SP::Digest, LocalError> {
    let value_hash = hash_serialized_value::<SP::Digest>(value)?;
    hash_value_hash_and_metadata::<SP>(&value_hash, metadata)
}

#[derive(Serialize, Deserialize)]
#[derive_where::derive_where(Debug, Clone)]
pub struct SignedValue<SP: SessionParameters> {
    signature: SP::Signature,
    // TODO: could be a part of the metadata and thus signed too,
    // but I don't think we get any additional security from it.
    source: SP::Verifier,
    metadata: ValueMetadata<SP::Verifier>,
    value: SerializedValue,
}

impl<SP: SessionParameters> SignedValue<SP> {
    pub(crate) fn new(
        rng: &mut impl CryptoRngCore,
        signer: &SP::Signer,
        name: &FullName,
        destination: &SP::Verifier,
        value: SerializedValue,
    ) -> Result<Self, LocalError> {
        let metadata = ValueMetadata::<SP::Verifier> {
            name: name.clone(),
            destination: destination.clone(),
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

    pub fn metadata(&self) -> &ValueMetadata<SP::Verifier> {
        &self.metadata
    }
}

#[derive(Serialize, Deserialize)]
#[derive_where::derive_where(Debug, Clone)]
pub struct SignedHash<SP: SessionParameters> {
    signature: SP::Signature,
    source: SP::Verifier,
    metadata: ValueMetadata<SP::Verifier>,
    #[serde(with = "GenericArray014::<Hex>")]
    hash: digest::Output<SP::Digest>,
}

impl<SP: SessionParameters> SignedHash<SP> {
    pub fn source(&self) -> &SP::Verifier {
        &self.source
    }

    pub fn metadata(&self) -> &ValueMetadata<SP::Verifier> {
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
    metadata: ValueMetadata<SP::Verifier>,
    value: SerializedValue,
}

impl<SP: SessionParameters> VerifiedValue<SP> {
    pub fn source(&self) -> &SP::Verifier {
        &self.source
    }

    pub fn metadata(&self) -> &ValueMetadata<SP::Verifier> {
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

    pub(crate) fn values(self) -> impl Iterator<Item = SignedValue<SP>> {
        self.values.into_iter()
    }
}
