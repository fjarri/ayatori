use alloc::{format, vec::Vec};

use serde::{Deserialize, Serialize};
use signature::{DigestVerifier, Keypair, RandomizedDigestSigner, digest::Digest, rand_core::CryptoRngCore};

use crate::{
    error::LocalError,
    protocol::{FullName, SerializedValue, SessionParameters, WireFormat},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ValueMetadata<Id> {
    name: FullName,
    destination: Id,
}

impl<Id> ValueMetadata<Id> {
    pub fn full_name(&self) -> &FullName {
        &self.name
    }
}

#[derive(Debug, Clone)]
pub(crate) enum VerificationError {
    Local(LocalError),
    SignatureMismatch,
}

impl From<LocalError> for VerificationError {
    fn from(source: LocalError) -> Self {
        Self::Local(source)
    }
}

#[derive(Serialize, Deserialize)]
#[derive_where::derive_where(Debug, Clone)]
pub(crate) struct SignedValue<SP: SessionParameters> {
    signature: SP::Signature,
    // TODO: could be a part of the metadata and thus signed too,
    // but I don't think we don't get any additional security from it.
    source: SP::Verifier,
    metadata: ValueMetadata<SP::Verifier>,
    value: SerializedValue,
}

impl<SP: SessionParameters> SignedValue<SP> {
    pub fn new(
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
        let value_len =
            u64::try_from(value.as_ref().len()).map_err(|_| LocalError::new("Message size exceeds 2^64 bytes"))?;
        let digest = SP::Digest::new_with_prefix(b"SignedValueDigest")
            .chain_update(<SP::WireFormat as WireFormat>::serialize(&metadata)?)
            .chain_update(value_len.to_be_bytes())
            .chain_update(value.as_ref());

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

    // TODO: produce a `Verified*` struct
    pub fn verify(&self) -> Result<(), VerificationError> {
        let value_len =
            u64::try_from(self.value.as_ref().len()).map_err(|_| LocalError::new("Message size exceeds 2^64 bytes"))?;
        let digest = SP::Digest::new_with_prefix(b"SignedValueDigest")
            .chain_update(<SP::WireFormat as WireFormat>::serialize(&self.metadata)?)
            .chain_update(value_len.to_be_bytes())
            .chain_update(self.value.as_ref());
        self.source
            .verify_digest(digest, &self.signature)
            .map_err(|_err| VerificationError::SignatureMismatch)?;
        Ok(())
    }

    pub fn metadata(&self) -> &ValueMetadata<SP::Verifier> {
        &self.metadata
    }

    pub fn serialized_value(&self) -> &SerializedValue {
        &self.value
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
