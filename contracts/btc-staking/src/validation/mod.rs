use crate::error::ContractError;
use babylon_apis::btc_staking_api::{BTCSigType, NewFinalityProvider, ProofOfPossessionBtc};
use babylon_bitcoin::schnorr::verify_digest;
use cosmwasm_std::CanonicalAddr;
use k256::{
    schnorr::{Signature, VerifyingKey},
    sha2::{Digest, Sha256},
};

/// verify_pop verifies the proof of possession of the given address.
fn verify_pop(
    btc_pk: &VerifyingKey,
    address: CanonicalAddr,
    pop: &ProofOfPossessionBtc,
) -> Result<(), ContractError> {
    // get signed msg, i.e., the hash of the canonicalised address
    let address_bytes = address.as_slice();
    let msg_hash: [u8; 32] = Sha256::new_with_prefix(address_bytes).finalize().into();

    // verify PoP
    let btc_sig_type = BTCSigType::try_from(pop.btc_sig_type)
        .map_err(|e| ContractError::FinalityProviderVerificationError(e.to_string()))?;
    match btc_sig_type {
        BTCSigType::BIP340 => {
            let pop_sig = Signature::try_from(pop.btc_sig.as_slice())
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            verify_digest(btc_pk, &msg_hash, &pop_sig)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
        }
        BTCSigType::BIP322 => {
            // TODO: implement BIP322 verification
            return Ok(());
        }
        BTCSigType::ECDSA => {
            // TODO: implement ECDSA verification
            return Ok(());
        }
    }

    Ok(())
}

/// verify_new_fp verifies the new finality provider data (lite version)
#[cfg(not(feature = "full-validation"))]
pub fn verify_new_fp(_new_fp: &NewFinalityProvider) -> Result<(), ContractError> {
    Ok(())
}

/// verify_new_fp verifies the new finality provider data (full validation version)
#[cfg(feature = "full-validation")]
pub fn verify_new_fp(new_fp: &NewFinalityProvider) -> Result<(), ContractError> {
    // get FP's PK

    use babylon_apis::new_canonical_addr;
    let fp_pk_bytes = hex::decode(&new_fp.btc_pk_hex)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
    let fp_pk = VerifyingKey::from_bytes(&fp_pk_bytes)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get canonicalised FP address
    // TODO: parameterise `bbn` prefix
    let addr = new_fp.addr.clone();
    let address = new_canonical_addr(&addr, "bbn")?;

    // get FP's PoP
    let pop = new_fp
        .pop
        .clone()
        .ok_or(ContractError::FinalityProviderVerificationError(
            "proof of possession is missing".to_string(),
        ))?;

    // verify PoP
    verify_pop(&fp_pk, address, &pop)?;

    Ok(())
}
