use core::num::NonZeroUsize;

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{GenericArray014, Hex};
use signature::{
    digest::{
        generic_array::typenum,
        {self},
    },
    rand_core::CryptoRngCore,
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestSignature<D: digest::Digest> {
    signed_by: u8,
    randomness: u64,
    #[serde(with = "GenericArray014::<Hex>")]
    signed_hash: digest::Output<D>,
}

impl TestSigner {
    /// Creates a new signer for testing purposes.
    #[must_use]
    pub fn new(id: u8) -> Self {
        Self(id)
    }
}

impl<D: digest::Digest> signature::RandomizedDigestSigner<D, TestSignature<D>> for TestSigner {
    fn try_sign_digest_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        digest: D,
    ) -> Result<TestSignature<D>, signature::Error> {
        Ok(TestSignature {
            signed_by: self.0,
            randomness: rng.next_u64(),
            signed_hash: digest.finalize(),
        })
    }
}

impl signature::Keypair for TestSigner {
    type VerifyingKey = TestVerifier;

    fn verifying_key(&self) -> Self::VerifyingKey {
        TestVerifier(self.0)
    }
}

impl<D: digest::Digest> signature::DigestVerifier<D, TestSignature<D>> for TestVerifier {
    fn verify_digest(&self, digest: D, signature: &TestSignature<D>) -> Result<(), signature::Error> {
        if self.0 == signature.signed_by && digest.finalize() == signature.signed_hash {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

/// A very simple hasher for testing purposes.
/// Not in any way secure.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestHasher {
    cursor: usize,
    buffer: digest::Output<Self>,
}

impl digest::HashMarker for TestHasher {}

impl digest::Update for TestHasher {
    fn update(&mut self, data: &[u8]) {
        // A very simple algorithm for testing, just xor the data in buffer-sized chunks.
        for byte in data {
            *self.buffer.get_mut(self.cursor).expect("index within bounds") ^= byte;

            let buffer_len = NonZeroUsize::new(self.buffer.len()).expect("buffer length is non-zero");

            // `cursor` is maintained `< buffer.len()`, so the addition will not overflow.
            self.cursor = (self.cursor.wrapping_add(1)) % buffer_len;
        }
    }
}

impl digest::FixedOutput for TestHasher {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        AsMut::<[u8]>::as_mut(out).copy_from_slice(&self.buffer);
    }
}

impl digest::OutputSizeUser for TestHasher {
    type OutputSize = typenum::U32;
}

/// An implementation of [`SessionParameters`] using the testing signer/verifier types.
#[derive(Debug, Clone, Copy)]
pub struct TestSessionParams<F>(core::marker::PhantomData<fn() -> F>);

impl<F: WireFormat> SessionParameters for TestSessionParams<F> {
    type Signer = TestSigner;
    type Verifier = TestVerifier;
    type Signature = TestSignature<Self::Digest>;
    type Digest = TestHasher;
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
