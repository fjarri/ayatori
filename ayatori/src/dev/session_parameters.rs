use core::hash::{BuildHasher, Hasher};

use ahash::{AHasher, RandomState};
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};
use signature::{
    digest::{
        array::typenum,
        {self},
    },
    rand_core::{CryptoRng, TryCryptoRng},
};

use crate::traits::{SessionParameters, WireFormat};

/// A simple signer for testing purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestSigner(u8);

/// A verifier corresponding to [`TestSigner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestVerifier(u8);
impl TestVerifier {
    /// Creates a new verifier for testing purposes.
    #[must_use]
    pub fn new(id: u8) -> Self {
        Self(id)
    }

    /// Access inner `u8`
    #[must_use]
    pub fn id(&self) -> u8 {
        self.0
    }
}

/// A signature produced by [`TestSigner`].
#[derive_where::derive_where(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestSignature<D: digest::FixedOutput> {
    signed_by: u8,
    randomness: u64,
    #[serde(with = "SliceLike::<Hex>")]
    signed_hash: digest::Output<D>,
}

impl TestSigner {
    /// Creates a new signer for testing purposes.
    #[must_use]
    pub fn new(id: u8) -> Self {
        Self(id)
    }
}

impl<D> signature::RandomizedDigestSigner<D, TestSignature<D>> for TestSigner
where
    D: digest::Update + digest::FixedOutput + Default,
{
    fn try_sign_digest_with_rng<R, F>(&self, rng: &mut R, f: F) -> Result<TestSignature<D>, signature::Error>
    where
        R: TryCryptoRng + ?Sized,
        F: Fn(&mut D) -> Result<(), signature::Error>,
    {
        let mut digest = D::default();
        f(&mut digest)?;
        let randomness = rng.try_next_u64().map_err(|_err| signature::Error::new())?;
        Ok(TestSignature {
            signed_by: self.0,
            randomness,
            signed_hash: digest.finalize_fixed(),
        })
    }
}

impl signature::Keypair for TestSigner {
    type VerifyingKey = TestVerifier;

    fn verifying_key(&self) -> Self::VerifyingKey {
        TestVerifier(self.0)
    }
}

impl<D> signature::DigestVerifier<D, TestSignature<D>> for TestVerifier
where
    D: digest::Digest + digest::FixedOutput + Default,
{
    fn verify_digest<F>(&self, f: F, signature: &TestSignature<D>) -> Result<(), signature::Error>
    where
        F: Fn(&mut D) -> Result<(), signature::Error>,
    {
        let mut digest = D::default();
        f(&mut digest)?;
        if self.0 == signature.signed_by && digest.finalize_fixed() == signature.signed_hash {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

/// A very simple hasher for testing purposes.
/// Not in any way secure.
#[derive(Debug, Clone)]
pub struct TestHasher(AHasher);

impl Default for TestHasher {
    fn default() -> Self {
        // `AHasher::default()` uses compile-time random numbers,
        // we want consistent defaults.
        Self(RandomState::with_seeds(1, 2, 3, 4).build_hasher())
    }
}

impl digest::HashMarker for TestHasher {}

impl digest::Update for TestHasher {
    fn update(&mut self, data: &[u8]) {
        self.0.write(data);
    }
}

impl digest::FixedOutput for TestHasher {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let result = Hasher::finish(&self.0).to_be_bytes();
        out.copy_from_slice(&result);
    }
}

impl digest::OutputSizeUser for TestHasher {
    type OutputSize = typenum::U8;
}

/// An implementation of [`SessionParameters`] using the testing signer/verifier types.
#[derive_where::derive_where(Debug, Clone, Copy)]
pub struct TestSessionParams<F, R>(core::marker::PhantomData<fn() -> (F, R)>);

impl<F: WireFormat, R: CryptoRng + 'static> SessionParameters for TestSessionParams<F, R> {
    type Signer = TestSigner;
    type Verifier = TestVerifier;
    type Signature = TestSignature<Self::Digest>;
    type Digest = TestHasher;
    type Rng = R;
    type WireFormat = F;
}

#[cfg(test)]
mod tests {
    use impls::impls;
    use signature::digest;

    use super::TestHasher;

    #[test]
    fn test_hasher_bounds() {
        assert!(impls!(TestHasher: digest::Digest));
    }
}
