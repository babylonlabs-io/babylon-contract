use crate::adaptor_sig::AdaptorSignature;
use crate::error::Error;
use crate::Result;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::Transaction;
use bitcoin::{Script, TxOut, XOnlyPublicKey};

fn calc_sighash(
    transaction: &Transaction,
    funding_output: &TxOut,
    path_script: &Script,
) -> Result<[u8; 32]> {
    // Check for incorrect input count
    if transaction.input.len() != 1 {
        return Err(Error::TxInputCountMismatch(1, transaction.input.len()));
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
) -> Result<()> {
    // calculate the sig hash of the tx for the given spending path
    let sighash = calc_sighash(transaction, funding_output, path_script)?;
    let sighash_msg = Message::from_digest(sighash);

    // verify the signature w.r.t. the signature, the sig hash, and the public key
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(signature, &sighash_msg, pub_key)
        .map_err(|e| Error::InvalidSchnorrSignature(e.to_string()))
}

/// enc_verify_transaction_sig_with_output verifies the validity of a Schnorr adaptor signature for a given transaction
pub fn enc_verify_transaction_sig_with_output(
    transaction: &Transaction,
    funding_output: &TxOut,
    path_script: &Script,
    pub_key: &XOnlyPublicKey,
    enc_key: &XOnlyPublicKey,
    signature: &AdaptorSignature,
) -> Result<()> {
    // calculate the sig hash of the tx for the given spending path
    let sighash_msg = calc_sighash(transaction, funding_output, path_script)?;

    // verify the signature w.r.t. the signature, the sig hash, and the public key
    signature.verify(pub_key, enc_key, sighash_msg)
}
