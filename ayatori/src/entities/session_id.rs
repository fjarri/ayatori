use core::fmt::{self, Debug};

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{GenericArray014, Hex};
use signature::digest::{self, Digest};
#[cfg(feature = "dev")]
use signature::rand_core::CryptoRngCore;

use crate::traits::SessionParameters;

/// A session identifier shared between the parties.
#[derive(Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[derive_where::derive_where(Clone, PartialEq, Eq)]
pub struct SessionId<SP: SessionParameters>(#[serde(with = "GenericArray014::<Hex>")] digest::Output<SP::Digest>);

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
    #[must_use]
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut buffer = digest::Output::<SP::Digest>::default();
        rng.fill_bytes(&mut buffer);
        Self(buffer)
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
    #[must_use]
    pub fn from_seed(bytes: &[u8]) -> Self {
        Self(SP::Digest::new_with_prefix(b"SessionId").chain_update(bytes).finalize())
    }
}

impl<SP: SessionParameters> AsRef<[u8]> for SessionId<SP> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<SP: SessionParameters> Debug for SessionId<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "SessionId({})", hex::encode(self.0.as_ref()))
    }
}
