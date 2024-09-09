use crate::error::ContractError;
use crate::state::config::Params;
use babylon_apis::btc_staking_api::{ActiveBtcDelegation, NewFinalityProvider};
use babylon_apis::btc_staking_api::{BTCSigType, ProofOfPossessionBtc};
use babylon_bitcoin::schnorr::verify_digest;
use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use cosmwasm_std::CanonicalAddr;
use hex::ToHex;
use k256::{
    schnorr::{Signature, VerifyingKey},
    sha2::{Digest, Sha256},
};
use std::str::FromStr;

#[cfg(feature = "full-validation")]
use bitcoin::Address;

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

/// verify_active_delegation is a placeholder for the full validation logic
///
/// It is marked with `#[cfg(feature = "full-validation")]` so that it
/// is not included in the build if the `full-validation` feature is disabled.
/// TODO: fix contract size when full-validation is enabled
#[cfg(feature = "full-validation")]
pub fn verify_active_delegation(
    params: &Params,
    active_delegation: &ActiveBtcDelegation,
    staking_tx: &Transaction,
) -> Result<(), ContractError> {
    // get staker's public key

    let staker_pk_bytes = hex::decode(&active_delegation.btc_pk_hex)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
    let staker_pk = VerifyingKey::from_bytes(&staker_pk_bytes)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get all FP's public keys
    let fp_pks: Vec<VerifyingKey> = active_delegation
        .fp_btc_pk_list
        .iter()
        .map(|pk_hex| {
            let pk_bytes =
                hex::decode(pk_hex).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
        })
        .collect::<Result<Vec<VerifyingKey>, ContractError>>()?;
    // get all covenant members' public keys
    let cov_pks: Vec<VerifyingKey> = params
        .covenant_pks
        .iter()
        .map(|pk_hex| {
            let pk_bytes =
                hex::decode(pk_hex).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
        })
        .collect::<Result<Vec<VerifyingKey>, ContractError>>()?;

    // Check if data provided in request, matches data to which staking tx is
    // committed

    // TODO: Check staking tx time-lock has correct values
    // get start_height and end_height of the time-lock

    // TODO: Ensure staking tx is k-deep

    // TODO: Ensure staking tx time-lock has more than w BTC blocks left

    // TODO: Verify staking tx info, i.e. inclusion proof

    // Check slashing tx and its consistency with staking tx
    let slashing_tx: Transaction = deserialize(&active_delegation.slashing_tx)
        .map_err(|_| ContractError::InvalidBtcTx(active_delegation.slashing_tx.encode_hex()))?;

    // decode slashing address
    let slashing_address: Address = Address::from_str(&params.slashing_address)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?
        .assume_checked();

    // Check slashing tx and staking tx are valid and consistent
    let slashing_rate = params
        .slashing_rate
        .parse::<f64>()
        .map_err(|_| ContractError::InvalidBtcTx("invalid slashing rate".to_string()))?;
    babylon_btcstaking::tx_verify::check_transactions(
        &slashing_tx,
        &staking_tx,
        active_delegation.staking_output_idx,
        params.min_slashing_tx_fee_sat,
        slashing_rate,
        &slashing_address,
        &staker_pk,
        active_delegation.unbonding_time as u16,
    )?;

    // TODO: Verify proof of possession

    /*
        verify staker signature against slashing path of the staking tx script
    */

    // get the slashing path script
    let staking_output = &staking_tx.output[active_delegation.staking_output_idx as usize];
    let staking_time = (active_delegation.end_height - active_delegation.start_height) as u16;
    let babylon_script_paths = babylon_btcstaking::scripts_utils::BabylonScriptPaths::new(
        &staker_pk,
        &fp_pks,
        &cov_pks,
        params.covenant_quorum as usize,
        staking_time,
    )?;
    let slashing_path_script = babylon_script_paths.slashing_path_script;

    // get the staker's signature on the slashing tx
    let staker_sig =
        k256::schnorr::Signature::try_from(active_delegation.delegator_slashing_sig.as_slice())
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // Verify the signature
    babylon_btcstaking::sig_verify::verify_transaction_sig_with_output(
        &slashing_tx,
        staking_output,
        slashing_path_script.as_script(),
        &staker_pk,
        &staker_sig,
    )
    .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // TODO: verify covenant signatures

    // TODO: Check unbonding time (staking time from unbonding tx) is larger than min unbonding time
    // which is larger value from:
    // - MinUnbondingTime
    // - CheckpointFinalizationTimeout

    // At this point, we know that unbonding time in request:
    // - is larger than min unbonding time
    // - is smaller than math.MaxUint16 (due to check in req.ValidateBasic())

    /*
        TODO: Early unbonding logic
    */

    // TODO: Deserialize provided transactions

    // TODO: Check that the unbonding tx input is pointing to staking tx

    // TODO: Check that staking tx output index matches unbonding tx output index

    // TODO: Build unbonding info

    // TODO: Get unbonding output index

    // TODO: Check that slashing tx and unbonding tx are valid and consistent

    // TODO: Check staker signature against slashing path of the unbonding tx

    // TODO: Verify covenant signatures over unbonding slashing tx

    // TODO: Check unbonding tx fees against staking tx
    // - Fee is greater than 0.
    // - Unbonding output value is at least `MinUnbondingValue` percentage of staking output value.

    Ok(())
}

/// verify_active_delegation is a placeholder for the full validation logic
///
/// It is marked with `#[cfg(not(feature = "full-validation"))]` so that it
/// is not included in the build if the `full-validation` feature is enabled.
#[cfg(not(feature = "full-validation"))]
pub fn verify_active_delegation(
    _params: &Params,
    _active_delegation: &ActiveBtcDelegation,
    _staking_tx: &Transaction,
) -> Result<(), ContractError> {
    Ok(())
}
