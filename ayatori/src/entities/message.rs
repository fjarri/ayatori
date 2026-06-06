use alloc::{boxed::Box, format, vec::Vec};
use core::fmt::{self, Debug};

use serde_encoded_bytes::{Hex, SliceLike};
use signature::{
    DigestVerifier, Keypair, RandomizedDigestSigner,
    digest::{self, FixedOutput, Update},
    rand_core::TryRng,
};

use super::{errors::RuntimeError, session_id::SessionId, tag::FullName, value::SerializedValue};
use crate::{
    traced_error::Traceable,
    traits::{SessionParameters, WireFormat},
};

/// Metadata of a signed value.
#[derive_where::derive_where(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueMetadata<SP: SessionParameters> {
    name: FullName,
    destination: SP::Verifier,
    session_id: SessionId<SP>,
}

impl<SP: SessionParameters> ValueMetadata<SP> {
    /// The name associated with the value.
    pub fn full_name(&self) -> &FullName {
        &self.name
    }

    /// The party the value is intended for.
    pub fn destination(&self) -> &SP::Verifier {
        &self.destination
    }

    /// The ID of the session in which the value was created.
    pub fn session_id(&self) -> &SessionId<SP> {
        &self.session_id
    }
}

/// A possible error when verifying a value signature.
#[derive(displaydoc::Display, Debug, Clone)]
pub enum VerificationError {
    /// Internal or environment error.
    #[displaydoc("{0}")]
    Runtime(RuntimeError),
    /// The signature is invalid.
    #[displaydoc("Signature mismatch")]
    SignatureMismatch,
}

impl From<RuntimeError> for VerificationError {
    fn from(source: RuntimeError) -> Self {
        Self::Runtime(source)
    }
}

impl core::error::Error for VerificationError {}

fn hash_serialized_value<D: Update + FixedOutput + Default>(value: &SerializedValue) -> digest::Output<D> {
    let value_len = u128::try_from(value.as_ref().len()).expect("Serialized value length is less than 2^128 bytes");
    let mut digest = D::default();
    digest.update(b"SerializedValueDigest");
    digest.update(&value_len.to_be_bytes());
    digest.update(value.as_ref());
    digest.finalize_fixed()
}

fn update_with_hash_and_metadata<SP: SessionParameters>(
    digest: &mut SP::Digest,
    value_hash: &digest::Output<SP::Digest>,
    metadata: &ValueMetadata<SP>,
) -> Result<(), signature::Error> {
    let serialized_metadata = <SP::WireFormat as WireFormat>::serialize(metadata).map_err(|err| {
        let err = err.with_context(format!(
            "Failed to serialize metadata for value `{}`",
            metadata.full_name()
        ));
        signature::Error::from_source(Box::new(err))
    })?;

    let metadata_len = u128::try_from(serialized_metadata.as_ref().len())
        .expect("Serialized metadata length is less than 2^128 bytes");

    digest.update(b"SignedValueDigest");
    digest.update(&metadata_len.to_be_bytes());
    digest.update(&serialized_metadata);
    digest.update(value_hash);
    Ok(())
}

fn update_with_value_and_metadata<SP: SessionParameters>(
    digest: &mut SP::Digest,
    value: &SerializedValue,
    metadata: &ValueMetadata<SP>,
) -> Result<(), signature::Error> {
    let value_hash = hash_serialized_value::<SP::Digest>(value);
    update_with_hash_and_metadata(digest, &value_hash, metadata)
}

/// A signed value with metadata.
#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
pub struct SignedValue<SP: SessionParameters> {
    signature: SP::Signature,
    source: SP::Verifier,
    metadata: ValueMetadata<SP>,
    value: SerializedValue,
}

impl<SP: SessionParameters> SignedValue<SP> {
    /// Signs a new value.
    pub fn new(
        rng: &mut SP::Rng,
        signer: &SP::Signer,
        session_id: &SessionId<SP>,
        name: &FullName,
        destination: &SP::Verifier,
        value: SerializedValue,
    ) -> Result<Self, RuntimeError> {
        let metadata = ValueMetadata {
            name: name.clone(),
            destination: destination.clone(),
            session_id: session_id.clone(),
        };
        //let digest = hash_value_and_metadata::<SP>(&value, &metadata)
        //    .or_with_context(|| format!("Failed to create a signed value `{name}`"))?;
        let signature = signer
            .try_sign_digest_with_rng(rng, |digest| update_with_value_and_metadata(digest, &value, &metadata))
            .map_err(|err| RuntimeError::new(format!("Signing failed: {err}")))?;
        Ok(Self {
            signature,
            source: signer.verifying_key(),
            metadata,
            value,
        })
    }

    /// The party that signed the value.
    pub fn source(&self) -> &SP::Verifier {
        &self.source
    }

    fn verify_inner(&self) -> Result<(), VerificationError> {
        self.source
            .verify_digest(
                |digest| update_with_value_and_metadata(digest, &self.value, &self.metadata),
                &self.signature,
            )
            .map_err(|_err| VerificationError::SignatureMismatch)
    }

    pub(crate) fn verify_and_unpack(self) -> Result<SerializedValue, VerificationError> {
        self.verify_inner()?;
        Ok(self.value)
    }

    /// Attempts to verify the value.
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

    /// Returns the associated metadata.
    pub fn metadata(&self) -> &ValueMetadata<SP> {
        &self.metadata
    }
}

/// A signed hash of the value and metadata.
#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHash<SP: SessionParameters> {
    signature: SP::Signature,
    source: SP::Verifier,
    metadata: ValueMetadata<SP>,
    #[serde(with = "SliceLike::<Hex>")]
    hash: digest::Output<SP::Digest>,
}

impl<SP: SessionParameters> SignedHash<SP> {
    /// The party that signed the value.
    pub fn source(&self) -> &SP::Verifier {
        &self.source
    }

    /// Returns the associated metadata.
    pub fn metadata(&self) -> &ValueMetadata<SP> {
        &self.metadata
    }

    fn verify_inner(&self) -> Result<(), VerificationError> {
        self.source
            .verify_digest(
                |digest| update_with_hash_and_metadata(digest, &self.hash, &self.metadata),
                &self.signature,
            )
            .map_err(|_err| VerificationError::SignatureMismatch)
    }

    /// Checks if the hash is correctly signed.
    pub fn is_signature_correct(&self) -> bool {
        self.verify_inner().is_ok()
    }
}

/// A signed value with the signature that has been verified and found correct.
#[derive_where::derive_where(Debug, Clone)]
pub struct VerifiedValue<SP: SessionParameters> {
    signature: SP::Signature,
    source: SP::Verifier,
    metadata: ValueMetadata<SP>,
    value: SerializedValue,
    message_id: MessageId<SP>,
}

impl<SP: SessionParameters> VerifiedValue<SP> {
    /// The party that signed the value.
    pub fn source(&self) -> &SP::Verifier {
        &self.source
    }

    /// Returns the associated metadata.
    pub fn metadata(&self) -> &ValueMetadata<SP> {
        &self.metadata
    }

    pub(crate) fn message_id(&self) -> &MessageId<SP> {
        &self.message_id
    }

    pub(crate) fn serialized_value(&self) -> &SerializedValue {
        &self.value
    }

    /// Returns `true` if the hash in `other` is equal to the hash of this value.
    pub fn payload_hash_matches(&self, other: &SignedHash<SP>) -> bool {
        let value_hash = hash_serialized_value::<SP::Digest>(&self.value);
        value_hash == other.hash
    }

    /// Turns this back into non-verified value (to send over the wire).
    pub fn unverify(self) -> SignedValue<SP> {
        SignedValue {
            signature: self.signature,
            source: self.source,
            metadata: self.metadata,
            value: self.value,
        }
    }

    /// Turns this into a signed hash (essentially replacing the actual value with its hash,
    /// keeping the metadata intact).
    pub fn to_signed_hash(&self) -> SignedHash<SP> {
        let value_hash = hash_serialized_value::<SP::Digest>(&self.value);
        SignedHash {
            signature: self.signature.clone(),
            source: self.source.clone(),
            metadata: self.metadata.clone(),
            hash: value_hash,
        }
    }
}

/// An ID associated with an incoming [`Message`](`crate::protocol_user_api::Message`).
///
/// The user is expected to generate and store the ID in association with the message source
/// (the nature of which will depend on the transport channel used).
/// If there is a problem with the message that cannot be associated with the specific verifier,
/// the returned error will contain the ID of the message the information came from.
/// Then, the user can use whatever measures necessary towards the associated source.
#[derive_where::derive_where(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct MessageId<SP: SessionParameters>(#[serde(with = "SliceLike::<Hex>")] digest::Output<SP::Digest>);

impl<SP: SessionParameters> MessageId<SP> {
    /// Creates a random message ID.
    pub fn random(rng: &mut SP::Rng) -> Result<Self, RuntimeError> {
        let mut buffer = digest::Output::<SP::Digest>::default();
        rng.try_fill_bytes(&mut buffer)
            .map_err(|err| RuntimeError::new(format!("Failed to invoke the RNG: {err}")))?;
        Ok(Self(buffer))
    }

    pub(crate) fn from_usize(id: usize) -> Self {
        let mut digest = SP::Digest::default();
        digest.update(&id.to_be_bytes());
        Self(digest.finalize_fixed())
    }
}

impl<SP: SessionParameters> Debug for MessageId<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "MessageId({})", hex::encode(&self.0))
    }
}

/// A message to be sent to another party, containing multiple signed values.
#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
pub struct Message<SP: SessionParameters> {
    destination: SP::Verifier,
    values: Vec<SignedValue<SP>>,
}

impl<SP: SessionParameters> Message<SP> {
    pub(crate) fn new(destination: SP::Verifier, values: Vec<SignedValue<SP>>) -> Self {
        // TODO: check that all the values have the same destination?
        Self { destination, values }
    }

    /// The party for which the message is intended.
    pub fn destination(&self) -> &SP::Verifier {
        &self.destination
    }

    pub(crate) fn into_values(self) -> Vec<SignedValue<SP>> {
        self.values
    }
}
