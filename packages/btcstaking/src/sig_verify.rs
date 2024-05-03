use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::Transaction;
use bitcoin::{Script, TxOut, XOnlyPublicKey};
use schnorr_fun::adaptor::{Adaptor, EncryptedSignature as AdaptorSignature};
use schnorr_fun::{Message as ASigMessage, Schnorr};
use secp256kfun::{marker::*, Point, Scalar};
use sha2::Sha256;

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

fn verify_adaptor_sig(
    pub_key: &XOnlyPublicKey,
    enc_key: &XOnlyPublicKey,
    msg: [u8; 32],
    asig: &AdaptorSignature,
) -> Result<(), String> {
    let verification_key = Point::from(*pub_key);
    let enc_key = Point::from(*enc_key);
    let parsed_msg = ASigMessage::<Public>::raw(&msg);
    let verifier = Schnorr::<Sha256>::verify_only();
    verifier.verify_encrypted_signature(&verification_key, &enc_key, parsed_msg, asig)
            .then_some(())
            .ok_or("failed to verify the adaptor signature".to_string())
}

pub fn new_adaptor_sig(asig_bytes: &[u8]) -> Result<AdaptorSignature, String> {
    if asig_bytes.len() != ADAPTOR_SIGNATURE_SIZE {
        return Err(format!("malformed bytes for an adaptor signature: expected: {}, actual: {}", ADAPTOR_SIGNATURE_SIZE, asig_bytes.len()));
    }
    let (r, _) = Point::from_slice(&asig_bytes[0..JACOBIAN_POINT_SIZE])
        .ok_or("failed to get R in an adaptor signature")?
        .into_point_with_even_y();
    let s_hat =
        Scalar::from_slice(&asig_bytes[JACOBIAN_POINT_SIZE..JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE])
            .ok_or("failed to get s_hat in an adaptor signature")?;
    let needs_negation = asig_bytes[JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE] == 0x01;
    Ok(AdaptorSignature {
        R: r,
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
