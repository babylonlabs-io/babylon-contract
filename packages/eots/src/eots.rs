use crate::error::Error;
use crate::Result;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{
    elliptic_curve::{
        ops::{MulByGenerator, Reduce},
        point::DecompressPoint,
        subtle::Choice,
        PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use sha2::{Digest, Sha256};
use std::ops::Mul;

const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

// adapted from https://github.com/RustCrypto/elliptic-curves/blob/520f67d26be1773bd600d05796cc26d797dd7182/k256/src/schnorr.rs#L181-L187
fn tagged_hash(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    // the hash is in sha256d so we need to hash twice
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest
}

/// SecRand is the type for a secret randomness
/// It is formed as a scalar on the Secp256k1 curve
pub type SecRand = Scalar;

/// new_sec_rand parses the given bytes into a new secret randomness
/// the given byte slice has to be a 32-byte scalar
pub fn new_sec_rand(r: &[u8]) -> Result<SecRand> {
    let array: [u8; 32] = r
        .try_into()
        .map_err(|_| Error::InvalidInputLength(r.len()))?;
    SecRand::from_repr_vartime(array.into()).ok_or(Error::SecretRandomnessParseFailed {})
}

/// PubRand is the type for a public randomness
/// It is formed as a point with even y coord on the Secp256k1 curve
pub type PubRand = ProjectivePoint;

/// new_pub_rand parses the given bytes into a new public randomness
/// the given byte slice has to be 32-byte representation of an x coordinate
/// on secp256k1 curve
pub fn new_pub_rand(x_bytes: &[u8]) -> Result<PubRand> {
    let array: [u8; 32] = x_bytes
        .try_into()
        .map_err(|_| Error::InvalidInputLength(x_bytes.len()))?;

    // Convert x_bytes to a FieldElement
    let x = k256::FieldBytes::from(array);

    // Attempt to derive the corresponding y-coordinate
    let ap_option = AffinePoint::decompress(&x, Choice::from(0));
    if ap_option.is_some().into() {
        Ok(ProjectivePoint::from(ap_option.unwrap()))
    } else {
        Err(Error::PublicRandomnessParseFailed {})
    }
}

/// Signature is an extractable one-time signature (EOTS)
/// i.e., s in a Schnorr signature (R, s)
pub type Signature = Scalar;

pub fn new_sig(r: &[u8]) -> Result<Signature> {
    let array: [u8; 32] = r
        .try_into()
        .map_err(|_| Error::InvalidInputLength(r.len()))?;
    Signature::from_repr_vartime(array.into()).ok_or(Error::SignatureParseFailed {})
}

/// SecretKey is a secret key, formed as a 32-byte scalar
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey {
    inner: k256::SecretKey,
}

/// PublicKey is a public key, formed as a point with even coordinate
/// on the Secp256k1 curve
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: k256::PublicKey,
}

fn point_to_bytes(p: &ProjectivePoint) -> [u8; 32] {
    let encoded_p = p.to_encoded_point(false);
    // Extract the x-coordinate as bytes
    let x_bytes = encoded_p.x().unwrap();
    let x_array: [u8; 32] = x_bytes.as_slice().try_into().unwrap(); // cannot fail
    x_array
}

#[allow(clippy::new_without_default)]
impl SecretKey {
    pub fn from_bytes(x: [u8; 32]) -> Result<Self> {
        let inner = Scalar::from_repr_vartime(x.into()).ok_or(Error::SecretKeyParseFailed {})?;

        let sk = k256::SecretKey::new(inner.into());
        Ok(SecretKey { inner: sk })
    }

    pub fn from_hex(x_hex: &str) -> Result<Self> {
        let x_slice = hex::decode(x_hex)?;
        let x: [u8; 32] = x_slice
            .clone()
            .try_into()
            .map_err(|_| Error::InvalidInputLength(x_slice.len()))?;

        SecretKey::from_bytes(x)
    }

    /// pubkey gets the public key corresponding to the secret key
    pub fn pubkey(&self) -> PublicKey {
        let pk = self.inner.public_key();
        PublicKey { inner: pk }
    }

    /// sign creates a signature with the given secret randomness
    /// and message hash
    pub fn sign(&self, sec_rand: &SecRand, msg_hash: &[u8; 32]) -> Signature {
        let x = self.inner.to_nonzero_scalar();
        let p = ProjectivePoint::mul_by_generator(&x);
        let p_bytes = point_to_bytes(&p);
        let r = *sec_rand;
        let r_point = ProjectivePoint::mul_by_generator(&r);
        let r_bytes = point_to_bytes(&r_point);
        let c = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_bytes)
                .chain_update(p_bytes)
                .chain_update(msg_hash)
                .finalize(),
        );

        r + c * *x
    }

    /// to_bytes converts the secret key into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

impl PublicKey {
    pub fn from_bytes(x_bytes: [u8; 32]) -> Result<Self> {
        let x = k256::FieldBytes::from(x_bytes);

        // Attempt to derive the corresponding y-coordinate
        let ap_option = AffinePoint::decompress(&x, Choice::from(0));
        if ap_option.is_some().into() {
            let pk = k256::PublicKey::from_affine(ap_option.unwrap())
                .map_err(|e| Error::EllipticCurveError(e.to_string()))?;
            Ok(PublicKey { inner: pk })
        } else {
            Err(Error::PublicKeyParseFailed {})
        }
    }

    pub fn from_hex(p_hex: &str) -> Result<Self> {
        let p_slice = hex::decode(p_hex)?;
        let p: [u8; 32] = p_slice
            .clone()
            .try_into()
            .map_err(|_| Error::InvalidInputLength(p_slice.len()))?;

        PublicKey::from_bytes(p)
    }

    /// to_bytes converts the public key into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        point_to_bytes(&self.inner.to_projective()).to_vec()
    }

    /// verify verifies whether the given signature w.r.t. the
    /// public key, public randomness and message hash
    pub fn verify(&self, pub_rand: &PubRand, msg_hash: &[u8; 32], sig: &Signature) -> bool {
        let p = self.inner.to_projective();
        let p_bytes = point_to_bytes(&p);
        let r = *pub_rand;
        let r_bytes = point_to_bytes(&r);
        let c = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_bytes)
                .chain_update(p_bytes)
                .chain_update(msg_hash)
                .finalize(),
        );

        let s = sig;
        let recovered_r = ProjectivePoint::mul_by_generator(s) - p.mul(c);
        recovered_r.eq(&r)
    }
}

/// extract extracts the secret key from the public key, public
/// randomness, and two pairs of message hashes and signatures
pub fn extract(
    pk: &PublicKey,
    pub_rand: &PubRand,
    msg1: &[u8; 32],
    sig1: &Signature,
    msg2: &[u8; 32],
    sig2: &Signature,
) -> Result<SecretKey> {
    let p = pk.inner.to_projective();
    let p_bytes = point_to_bytes(&p);
    let r = *pub_rand;
    let r_bytes = point_to_bytes(&r);

    // calculate e1 - e2
    let e1 = <Scalar as Reduce<U256>>::reduce_bytes(
        &tagged_hash(CHALLENGE_TAG)
            .chain_update(r_bytes)
            .chain_update(p_bytes)
            .chain_update(msg1)
            .finalize(),
    );
    let e2 = <Scalar as Reduce<U256>>::reduce_bytes(
        &tagged_hash(CHALLENGE_TAG)
            .chain_update(r_bytes)
            .chain_update(p_bytes)
            .chain_update(msg2)
            .finalize(),
    );
    let e_delta = e1 - e2;

    // calculate s1 - s2
    let s1 = sig1;
    let s2 = sig2;
    let s_delta = s1 - s2;

    // calculate (s1-s2) / (e1 - e2)
    let inverted_e_delta = e_delta.invert().unwrap();
    let sk = s_delta * inverted_e_delta;
    let sk = k256::SecretKey::new(sk.into());
    Ok(SecretKey { inner: sk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};
    use sha2::{Digest, Sha256};
    use test_utils::get_eots_testdata;

    use k256::{ProjectivePoint, Scalar};

    pub fn rand_gen() -> (SecRand, PubRand) {
        let x = Scalar::generate_vartime(&mut thread_rng());
        let p = ProjectivePoint::mul_by_generator(&x);
        (x, p)
    }

    impl Default for SecretKey {
        fn default() -> Self {
            let rng = &mut thread_rng();
            Self::new(rng)
        }
    }

    impl SecretKey {
        /// new creates a random secret key
        pub fn new<R: RngCore>(rng: &mut R) -> Self {
            let x = Scalar::generate_vartime(rng);
            let x = k256::SecretKey::new(x.into());
            SecretKey { inner: x }
        }
    }

    #[test]
    fn test_sign_verify() {
        let sk = SecretKey::new(&mut thread_rng());
        let pk = sk.pubkey();
        let (sec_rand, pub_rand) = rand_gen();
        let msg_hash = [1u8; 32];
        let sig = sk.sign(&sec_rand, &msg_hash);
        assert!(pk.verify(&pub_rand, &msg_hash, &sig));
    }

    #[test]
    fn test_extract() {
        let sk = SecretKey::new(&mut thread_rng());
        let pk = sk.pubkey();
        let (sec_rand, pub_rand) = rand_gen();
        let msg_hash1 = [1u8; 32];
        let msg_hash2 = [2u8; 32];
        let sig1 = sk.sign(&sec_rand, &msg_hash1);
        let sig2 = sk.sign(&sec_rand, &msg_hash2);

        let extracted_sk = extract(&pk, &pub_rand, &msg_hash1, &sig1, &msg_hash2, &sig2).unwrap();
        assert_eq!(sk.pubkey().to_bytes(), extracted_sk.pubkey().to_bytes());
    }

    #[test]
    fn test_serialize() {
        let testdata = get_eots_testdata();

        // convert SK and PK from bytes to Rust types
        let sk = SecretKey::from_hex(&testdata.sk).unwrap();
        let pk = PublicKey::from_hex(&testdata.pk).unwrap();
        assert_eq!(sk.pubkey().to_bytes(), pk.to_bytes());

        // convert secret/public randomness to Rust types
        let sr_slice = hex::decode(testdata.sr).unwrap();
        let sr = new_sec_rand(&sr_slice).unwrap();
        let pr_slice = hex::decode(testdata.pr).unwrap();
        let pr_bytes: [u8; 32] = pr_slice.try_into().unwrap();
        let pr = new_pub_rand(&pr_bytes).unwrap();
        assert_eq!(ProjectivePoint::mul_by_generator(&sr), pr);

        // convert messages
        let mut hasher = Sha256::new();
        let msg1_slice = hex::decode(testdata.msg1).unwrap();
        hasher.update(msg1_slice);
        let msg1_hash: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        let msg2_slice = hex::decode(testdata.msg2).unwrap();
        hasher.update(msg2_slice);
        let msg2_hash: [u8; 32] = hasher.finalize().into();

        // convert signatures
        let sig1_slice = hex::decode(testdata.sig1).unwrap();
        let sig1 = new_sig(&sig1_slice).unwrap();
        let sig2_slice = hex::decode(testdata.sig2).unwrap();
        let sig2 = new_sig(&sig2_slice).unwrap();

        // verify signatures
        assert!(pk.verify(&pr, &msg1_hash, &sig1));
        assert!(pk.verify(&pr, &msg2_hash, &sig2));

        // extract SK
        let extracted_sk = extract(&pk, &pr, &msg1_hash, &sig1, &msg2_hash, &sig2).unwrap();
        assert_eq!(sk.pubkey().to_bytes(), extracted_sk.pubkey().to_bytes());
    }
}
