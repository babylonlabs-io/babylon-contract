//! Dummy 256-bits Digest impl.
//! This digest stores/accepts a value of the proper length.
//! To be used for / with already hashed values, just to comply with the Digest contract.
//!
//! Adapted from `sha2` [sha256.rs](https://github.com/RustCrypto/hashes/blob/master/sha2/src/sha256.rs)
//! and https://github.com/CosmWasm/cosmwasm/blob/main/packages/crypto/src/identity_digest.rs
use crate::error::Error;
use crate::Result;
use digest::consts::U32;
use digest::generic_array::GenericArray;
use digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Reset, Update};
use k256::schnorr::signature::DigestVerifier;
use k256::schnorr::Signature as SchnorrSignature;
use k256::schnorr::VerifyingKey;
use sha2::Digest;

/// The 256-bits identity container
#[derive(Clone, Default)]
pub struct Identity256 {
    array: GenericArray<u8, U32>,
}

impl Update for Identity256 {
    fn update(&mut self, hash: &[u8]) {
        assert_eq!(hash.as_ref().len(), 32);
        self.array = *GenericArray::from_slice(hash);
    }
}

impl OutputSizeUser for Identity256 {
    type OutputSize = U32;
}

impl FixedOutput for Identity256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        *out = self.array;
    }
}

impl HashMarker for Identity256 {}

impl Reset for Identity256 {
    fn reset(&mut self) {
        *self = Self::default();
    }
}

pub fn new_digest(msg_hash: &[u8; 32]) -> Identity256 {
    Identity256::new().chain(msg_hash)
}

pub fn verify_digest(
    pub_key: &VerifyingKey,
    msg_hash: &[u8; 32],
    signature: &SchnorrSignature,
) -> Result<()> {
    let digest = new_digest(msg_hash);

    pub_key
        .verify_digest(digest, signature)
        .map_err(|e| Error::InvalidSchnorrSignature(e.to_string()))
}
