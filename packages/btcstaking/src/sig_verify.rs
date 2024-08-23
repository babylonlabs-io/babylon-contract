use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use bitcoin::secp256k1::Message;
use bitcoin::secp256k1::Parity;
use bitcoin::secp256k1::PublicKey;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::Transaction;
use bitcoin::{Script, TxOut, XOnlyPublicKey};
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::pkcs8::der::Choice;
use k256::{
    elliptic_curve::{
        ops::{MulByGenerator, Reduce},
        point::{AffineCoordinates, DecompressPoint},
        PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use sha2::{Digest, Sha256};

/// MODNSCALAR_SIZE is the size of a scalar on the secp256k1 curve
const MODNSCALAR_SIZE: usize = 32;

/// MODNSCALAR_SIZE is the size of a point on the secp256k1 curve in
/// compressed form
const JACOBIAN_POINT_SIZE: usize = 33;

/// ADAPTOR_SIGNATURE_SIZE is the size of a Schnorr adaptor signature
/// It is in the form of (R, s, needsNegation) where `R` is a point,
/// `s` is a scalar, and `needsNegation` is a boolean value
const ADAPTOR_SIGNATURE_SIZE: usize = JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE + 1;

fn calc_sighash(
    transaction: &Transaction,
    funding_output: &TxOut,
    path_script: &Script,
) -> Result<[u8; 32], String> {
    // Check for incorrect input count
    if transaction.input.len() != 1 {
        return Err("tx to sign must have exactly one input".into());
    }

    // calculate tap leaf hash for the given path of the script
    let tap_leaf_hash = path_script.tapscript_leaf_hash();

    // calculate the sig hash of the tx with the given funding output
    let mut sighash_cache = SighashCache::new(transaction);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[funding_output]),
            tap_leaf_hash,
            bitcoin::TapSighashType::Default,
        )
        .unwrap();

    Ok(sighash.to_raw_hash().to_byte_array())
}

/// verify_transaction_sig_with_output verifies the validity of a Schnorr signature for a given transaction
pub fn verify_transaction_sig_with_output(
    transaction: &Transaction,
    funding_output: &TxOut,
    path_script: &Script,
    pub_key: &XOnlyPublicKey,
    signature: &SchnorrSignature,
) -> Result<(), String> {
    // calculate the sig hash of the tx for the given spending path
    let sighash = calc_sighash(transaction, funding_output, path_script)?;
    let sighash_msg = Message::from_digest(sighash);

    // verify the signature w.r.t. the signature, the sig hash, and the public key
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(signature, &sighash_msg, pub_key)
        .map_err(|e| e.to_string())
}

pub struct AdaptorSignature {
    R: ProjectivePoint,
    s_hat: Scalar,
    needs_negation: bool,
}

const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

// Adapted from https://github.com/RustCrypto/elliptic-curves/blob/520f67d26be1773bd600d05796cc26d797dd7182/k256/src/schnorr.rs#L181-L187
fn tagged_hash(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    // The hash is in sha256d, so we need to hash twice
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest
}

#[allow(non_snake_case)]
fn bytes_to_point(bytes: &[u8]) -> Result<ProjectivePoint, String> {
    let is_y_odd = bytes[0] == 0x03;
    let R_option = AffinePoint::decompress(
        k256::FieldBytes::from_slice(&bytes[1..]),
        k256::elliptic_curve::subtle::Choice::from(is_y_odd as u8),
    );
    let R = if R_option.is_some().into() {
        R_option.unwrap()
    } else {
        return Err("Failed to decompress R point".to_string());
    };
    // Convert AffinePoint to ProjectivePoint
    Ok(ProjectivePoint::from(R))
}

#[allow(non_snake_case)]
fn verify_adaptor_sig(
    pub_key: &XOnlyPublicKey,
    enc_key: &XOnlyPublicKey,
    msg: [u8; 32],
    asig: &AdaptorSignature,
) -> Result<(), String> {
    // Convert public keys to points
    let pk = pub_key.public_key(Parity::Even);
    let P = bytes_to_point(&pk.serialize())?;
    let ek = enc_key.public_key(Parity::Even);
    let T = bytes_to_point(&ek.serialize())?;

    // Calculate R' = R - T (or R + T if negation is needed)
    let R_hat = if asig.needs_negation {
        asig.R + T
    } else {
        asig.R - T
    };
    // Convert R' to affine coordinates
    let R_hat = R_hat.to_affine();

    // Calculate e = tagged_hash("BIP0340/challenge", bytes(R') || bytes(P) || m)
    // mod n
    let R_bytes = R_hat.x();
    let p_bytes = pub_key.serialize();
    let e = <Scalar as Reduce<U256>>::reduce_bytes(
        &tagged_hash(CHALLENGE_TAG)
            .chain_update(R_bytes)
            .chain_update(p_bytes)
            .chain_update(msg)
            .finalize(),
    );

    // Calculate expected R' = s'*G - e*P
    let s_hat_g = ProjectivePoint::mul_by_generator(&asig.s_hat);
    let e_p = P * e;
    let expected_R_hat = s_hat_g - e_p;

    // Convert expected R' to affine coordinates
    let expected_R_hat = expected_R_hat.to_affine();

    // Ensure expected R' is not the point at infinity
    if expected_R_hat.is_identity().into() {
        return Err("Expected R' is the point at infinity".to_string());
    }

    // Ensure expected R'.y is even
    if expected_R_hat.y_is_odd().into() {
        return Err("Expected R'.y is odd".to_string());
    }

    // Ensure R' == expected R'
    if !R_hat.eq(&expected_R_hat) {
        return Err("R' does not match expected R'".to_string());
    }

    Ok(())
}

#[allow(non_snake_case)]
pub fn new_adaptor_sig(asig_bytes: &[u8]) -> Result<AdaptorSignature, String> {
    if asig_bytes.len() != ADAPTOR_SIGNATURE_SIZE {
        return Err(format!(
            "malformed bytes for an adaptor signature: expected: {}, actual: {}",
            ADAPTOR_SIGNATURE_SIZE,
            asig_bytes.len()
        ));
    }
    // get R
    let is_y_odd = asig_bytes[0] == 0x03;
    let R_option = AffinePoint::decompress(
        k256::FieldBytes::from_slice(&asig_bytes[1..JACOBIAN_POINT_SIZE]),
        k256::elliptic_curve::subtle::Choice::from(is_y_odd as u8),
    );
    let R = if R_option.is_some().into() {
        R_option.unwrap().into()
    } else {
        return Err("Failed to decompress R point".to_string());
    };

    // get s_hat
    let s_hat_bytes = &asig_bytes[JACOBIAN_POINT_SIZE..JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE];
    let s_hat_field_bytes = *k256::FieldBytes::from_slice(s_hat_bytes);
    let s_hat = Scalar::from_repr_vartime(s_hat_field_bytes)
        .ok_or("failed to get s_hat in an adaptor signature")?;

    let needs_negation = asig_bytes[JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE] == 0x01;
    Ok(AdaptorSignature {
        R: R,
        s_hat,
        needs_negation,
    })
}

/// enc_verify_transaction_sig_with_output verifies the validity of a Schnorr adaptor signature for a given transaction
pub fn enc_verify_transaction_sig_with_output(
    transaction: &Transaction,
    funding_output: &TxOut,
    path_script: &Script,
    pub_key: &XOnlyPublicKey,
    enc_key: &XOnlyPublicKey,
    signature: &AdaptorSignature,
) -> Result<(), String> {
    // calculate the sig hash of the tx for the given spending path
    let sighash_msg = calc_sighash(transaction, funding_output, path_script)?;

    // verify the signature w.r.t. the signature, the sig hash, and the public key
    verify_adaptor_sig(pub_key, enc_key, sighash_msg, signature)
}
