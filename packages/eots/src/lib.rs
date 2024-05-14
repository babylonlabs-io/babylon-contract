#![allow(non_snake_case)]

use secp256kfun::{
    g,
    hash::{HashAdd, Tag},
    marker::*,
    s, Point, Scalar, G,
};
use sha2::Sha256;

/// SecRand is the type for a secret randomness
/// It is formed as a scalar on the Secp256k1 curve
pub type SecRand = Scalar;
/// PubRand is the type for a public randomness
/// It is formed as a point with even y coord on the Secp256k1 curve
pub type PubRand = Point<EvenY>;

/// Signature is an extractable one-time signature (EOTS)
/// i.e., s in a Schnorr signature (R, s)
pub type Signature = Scalar<Public, Zero>;

/// bip340_challenge is the hash function with magic bytes specified
/// by BIP-340
fn bip340_challenge() -> Sha256 {
    Sha256::default().tag(b"BIP0340/challenge")
}

/// SecretKey is a secret key, formed as a 32-byte scalar
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey {
    inner: Scalar,
}

/// PublicKey is a public key, formed as a point with even coordinate
/// on the Secp256k1 curve
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: Point<EvenY>,
}

#[allow(clippy::new_without_default)]
impl SecretKey {
    pub fn from_bytes(x: [u8; 32]) -> Result<Self, String> {
        let inner = Scalar::from_bytes(x).ok_or("failed to convert bytes to secret key")?;
        Ok(SecretKey { inner })
    }

    pub fn from_hex(x_hex: &str) -> Result<Self, String> {
        let x_slice = hex::decode(x_hex).map_err(|e| e.to_string())?;
        let x: [u8; 32] = x_slice.try_into().map_err(|_| "wrong hex string length")?;
        SecretKey::from_bytes(x)
    }

    /// pubkey gets the public key corresponding to the secret key
    pub fn pubkey(&self) -> PublicKey {
        let mut x = self.inner;
        let P = Point::even_y_from_scalar_mul(G, &mut x);
        PublicKey { inner: P }
    }

    /// sign creates a signature with the given secret randomness
    /// and message hash
    pub fn sign(&self, sec_rand: &SecRand, msg_hash: &[u8; 32]) -> Signature {
        let mut x = self.inner;
        let P = Point::even_y_from_scalar_mul(G, &mut x);
        let mut r = *sec_rand;
        let R = Point::even_y_from_scalar_mul(G, &mut r);
        let c = Scalar::from_hash(bip340_challenge().add(R).add(P).add(msg_hash));
        let s = s!(r + c * x); // TODO: get rid of s! and g! macros

        s.public()
    }

    /// to_bytes converts the secret key into bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

impl PublicKey {
    pub fn from_bytes(P: [u8; 32]) -> Result<Self, String> {
        let inner =
            Point::<EvenY>::from_xonly_bytes(P).ok_or("failed to convert bytes to public key")?;
        Ok(PublicKey { inner })
    }

    pub fn from_hex(P_hex: &str) -> Result<Self, String> {
        let P_slice = hex::decode(P_hex).map_err(|e| e.to_string())?;
        let P: [u8; 32] = P_slice.try_into().map_err(|_| "wrong hex string length")?;
        PublicKey::from_bytes(P)
    }

    /// to_bytes converts the public key into bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_xonly_bytes()
    }

    /// verify verifies whether the given signature w.r.t. the
    /// public key, public randomness and message hash
    pub fn verify(&self, pub_rand: &PubRand, msg_hash: &[u8; 32], sig: &Signature) -> bool {
        let P = self.inner;
        let R = *pub_rand;
        let c = Scalar::from_hash(bip340_challenge().add(R).add(P).add(msg_hash)).public();
        let s = sig;
        g!(s * G - c * P) == R
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
) -> Result<SecretKey, String> {
    let P = pk.inner;
    let R = *pub_rand;

    let e1 = Scalar::from_hash(bip340_challenge().add(R).add(P).add(msg1)).public();
    let e2 = Scalar::from_hash(bip340_challenge().add(R).add(P).add(msg2)).public();
    let e_delta = s!(e1 - e2).public();

    let s1 = sig1;
    let s2 = sig2;
    let s_delta = s!(s1 - s2).public();

    let e_delta = e_delta.non_zero().ok_or("zero e_delta".to_string())?;
    let invrted_e_delta = e_delta.invert();
    let sk = s!(s_delta * invrted_e_delta);
    let sk = sk.non_zero().ok_or("zero sk".to_string())?;
    Ok(SecretKey { inner: sk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};
    use sha2::{Digest, Sha256};
    use test_utils::get_eots_testdata;

    pub fn rand_gen() -> (SecRand, PubRand) {
        let mut x = Scalar::random(&mut thread_rng());
        let P = Point::even_y_from_scalar_mul(G, &mut x);
        (x, P)
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
            let x = Scalar::random(rng);
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
        let sr = SecRand::from_slice(&sr_slice).unwrap();
        let pr_slice = hex::decode(testdata.pr).unwrap();
        let pr_bytes: [u8; 32] = pr_slice.try_into().unwrap();
        let pr = PubRand::from_xonly_bytes(pr_bytes).unwrap();
        let mut r = sr;
        assert_eq!(Point::even_y_from_scalar_mul(G, &mut r), pr);

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
        let sig1 = Signature::from_slice(&sig1_slice).unwrap();
        let sig2_slice = hex::decode(testdata.sig2).unwrap();
        let sig2 = Signature::from_slice(&sig2_slice).unwrap();

        // verify signatures
        assert!(pk.verify(&pr, &msg1_hash, &sig1));
        assert!(pk.verify(&pr, &msg2_hash, &sig2));

        // extract SK
        let extracted_sk = extract(&pk, &pr, &msg1_hash, &sig1, &msg2_hash, &sig2).unwrap();
        assert_eq!(sk.pubkey().to_bytes(), extracted_sk.pubkey().to_bytes());
    }
}
