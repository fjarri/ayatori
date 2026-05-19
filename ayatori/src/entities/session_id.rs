use core::fmt::{self, Debug};

use serde_encoded_bytes::{Hex, SliceLike};
use signature::digest::{self, FixedOutput, Update};

use crate::traits::SessionParameters;

#[cfg(feature = "dev")]
use ::{alloc::format, signature::rand_core::TryRng};

#[cfg(feature = "dev")]
use crate::entities::RuntimeError;

/// A session identifier shared between the parties.
#[derive_where::derive_where(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct SessionId<SP: SessionParameters>(#[serde(with = "SliceLike::<Hex>")] digest::Output<SP::Digest>);

/// A session ID.
///
/// This must be the same for all nodes executing a session.
///
/// Must be created uniquely for each session execution, otherwise there is a danger of replay attacks.
impl<SP: SessionParameters> SessionId<SP> {
    /// Creates a random session identifier.
    ///
    /// **Warning:** this should generally be used for testing; creating a random session ID in a centralized way
    /// usually defeats the purpose of having a distributed protocol.
    #[cfg(feature = "dev")]
    pub fn random(rng: &mut SP::Rng) -> Result<Self, RuntimeError> {
        let mut buffer = digest::Output::<SP::Digest>::default();
        rng.try_fill_bytes(&mut buffer)
            .map_err(|err| RuntimeError::new(format!("Failed to invoke the RNG: {err}")))?;
        Ok(Self(buffer))
    }

    /// Creates a session identifier deterministically from the given bytestring.
    ///
    /// Every node executing a session must be given the same session ID.
    ///
    /// **Warning:** make sure the bytestring you provide will not be reused within your application,
    /// and cannot be predicted in advance.
    /// Session ID collisions will affect error attribution and evidence verification.
    ///
    /// In a blockchain setting, it may be some combination of the current block hash with the public parameters
    /// (identities of the parties, hash of the inputs).
    ///
    /// # Panics
    ///
    /// Panics if the seed is 2^128 bytes or larger.
    #[must_use]
    pub fn from_seed(bytes: &[u8]) -> Self {
        let bytes_len = u128::try_from(bytes.len()).expect("Seed length is less than 2^128 bytes");
        let mut digest = SP::Digest::default();
        digest.update(b"SessionId");
        digest.update(&bytes_len.to_be_bytes());
        digest.update(bytes);
        Self(digest.finalize_fixed())
    }
}

impl<SP: SessionParameters> AsRef<[u8]> for SessionId<SP> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<SP: SessionParameters> Debug for SessionId<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "SessionId({})", hex::encode(&self.0))
    }
}
