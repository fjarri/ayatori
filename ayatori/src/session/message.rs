use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};
use signature::{DigestVerifier, Keypair, RandomizedDigestSigner, digest::Digest, rand_core::CryptoRngCore};

use crate::protocol::{SerializedValue, SessionParameters, WireFormat};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ValueMetadata<Id> {
    name: String,
    destination: Id,
}

impl<Id> ValueMetadata<Id> {
    pub fn name(&self) -> &str {
        &self.name
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
        name: &str,
        destination: &SP::Verifier,
        value: SerializedValue,
    ) -> Self {
        let metadata = ValueMetadata::<SP::Verifier> {
            name: name.into(),
            destination: destination.clone(),
        };
        let value_len = u64::try_from(value.as_ref().len()).unwrap();
        let digest = SP::Digest::new_with_prefix(b"SignedValueDigest")
            .chain_update(<SP::WireFormat as WireFormat>::serialize(&metadata).unwrap())
            .chain_update(value_len.to_be_bytes())
            .chain_update(value.as_ref());

        let signature = signer.try_sign_digest_with_rng(rng, digest).unwrap();
        Self {
            signature,
            source: signer.verifying_key(),
            metadata,
            value,
        }
    }

    pub fn source(&self) -> &SP::Verifier {
        &self.source
    }

    // TODO: produce a `Verified*` struct
    pub fn verify(&self) -> Option<()> {
        let value_len = u64::try_from(self.value.as_ref().len()).unwrap();
        let digest = SP::Digest::new_with_prefix(b"SignedValueDigest")
            .chain_update(<SP::WireFormat as WireFormat>::serialize(&self.metadata).unwrap())
            .chain_update(value_len.to_be_bytes())
            .chain_update(self.value.as_ref());
        self.source.verify_digest(digest, &self.signature).unwrap();
        Some(())
    }

    pub fn metadata(&self) -> &ValueMetadata<SP::Verifier> {
        &self.metadata
    }

    pub fn serialized_value(self) -> SerializedValue {
        self.value
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
