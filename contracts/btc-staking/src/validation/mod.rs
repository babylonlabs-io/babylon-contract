use crate::state::config::Params;
use crate::{error::ContractError, state::staking::BtcDelegation};
use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, NewFinalityProvider, SlashedBtcDelegation, UnbondedBtcDelegation,
};
use bitcoin::Transaction;
use cosmwasm_std::Binary;

#[cfg(feature = "full-validation")]
use {
    babylon_apis::btc_staking_api::{BTCSigType, ProofOfPossessionBtc},
    babylon_bitcoin::schnorr::verify_digest,
    bitcoin::{consensus::deserialize, Address},
    cosmwasm_std::CanonicalAddr,
    hex::ToHex,
    k256::schnorr::{Signature, VerifyingKey},
    k256::sha2::{Digest, Sha256},
    std::str::FromStr,
};

/// verify_pop verifies the proof of possession of the given address.
#[cfg(feature = "full-validation")]
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

#[cfg(feature = "full-validation")]
fn get_pks(
    staker_pk_hex: String,
    fp_pk_hex_list: Vec<String>,
    cov_pk_hex_list: Vec<String>,
) -> Result<(VerifyingKey, Vec<VerifyingKey>, Vec<VerifyingKey>), ContractError> {
    // get staker's public key
    let staker_pk_bytes =
        hex::decode(&staker_pk_hex).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
    let staker_pk = VerifyingKey::from_bytes(&staker_pk_bytes)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get all FP's public keys
    let fp_pks: Vec<VerifyingKey> = fp_pk_hex_list
        .iter()
        .map(|pk_hex| {
            let pk_bytes =
                hex::decode(pk_hex).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
        })
        .collect::<Result<Vec<VerifyingKey>, ContractError>>()?;
    // get all covenant members' public keys
    let cov_pks: Vec<VerifyingKey> = cov_pk_hex_list
        .iter()
        .map(|pk_hex| {
            let pk_bytes =
                hex::decode(pk_hex).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
        })
        .collect::<Result<Vec<VerifyingKey>, ContractError>>()?;

    Ok((staker_pk, fp_pks, cov_pks))
}

/// verify_new_fp verifies the new finality provider data (full validation version)
pub fn verify_new_fp(new_fp: &NewFinalityProvider) -> Result<(), ContractError> {
    // The following code is marked with `#[cfg(feature = "full-validation")]`
    // so that it is included in the build if the `full-validation` feature is
    // enabled.
    // TODO: fix contract size when full-validation is enabled
    #[cfg(feature = "full-validation")]
    {
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
    }

    // make static analyser happy with unused parameters
    #[cfg(not(feature = "full-validation"))]
    let _ = new_fp;

    Ok(())
}

/// verify_active_delegation verifies the active delegation data
pub fn verify_active_delegation(
    params: &Params,
    active_delegation: &ActiveBtcDelegation,
    staking_tx: &Transaction,
) -> Result<(), ContractError> {
    // The following code is marked with `#[cfg(feature = "full-validation")]`
    // so that it is included in the build if the `full-validation` feature is
    // enabled.
    // TODO: fix contract size when full-validation is enabled
    #[cfg(feature = "full-validation")]
    {
        let (staker_pk, fp_pks, cov_pks) = get_pks(
            active_delegation.btc_pk_hex.clone(),
            active_delegation.fp_btc_pk_list.clone(),
            params.covenant_pks.clone(),
        )?;

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
            staking_tx,
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
    }

    // make static analyser happy with unused parameters
    #[cfg(not(feature = "full-validation"))]
    let _ = (params, active_delegation, staking_tx);

    Ok(())
}

pub fn verify_undelegation(
    params: &Params,
    btc_del: &BtcDelegation,
    sig: &Binary,
) -> Result<(), ContractError> {
    // The following code is marked with `#[cfg(feature = "full-validation")]`
    // so that it is included in the build if the `full-validation` feature is
    // enabled.
    // TODO: fix contract size when full-validation is enabled
    #[cfg(feature = "full-validation")]
    {
        // TODO: Verify the signature on the unbonding tx is from the delegator

        // get keys
        let (staker_pk, fp_pks, cov_pks) = get_pks(
            btc_del.btc_pk_hex.clone(),
            btc_del.fp_btc_pk_list.clone(),
            params.covenant_pks.clone(),
        )?;

        // get the unbonding path script
        let staking_tx: Transaction = deserialize(&btc_del.staking_tx)
            .map_err(|_| ContractError::InvalidBtcTx(btc_del.staking_tx.encode_hex()))?;
        let staking_output = &staking_tx.output[btc_del.staking_output_idx as usize];
        let staking_time = (btc_del.end_height - btc_del.start_height) as u16;
        let babylon_script_paths = babylon_btcstaking::scripts_utils::BabylonScriptPaths::new(
            &staker_pk,
            &fp_pks,
            &cov_pks,
            params.covenant_quorum as usize,
            staking_time,
        )?;
        let unbonding_path_script = babylon_script_paths.unbonding_path_script;

        // get unbonding tx
        let unbonding_tx: Transaction = deserialize(&btc_del.undelegation_info.unbonding_tx)
            .map_err(|_| {
                ContractError::InvalidBtcTx(btc_del.undelegation_info.unbonding_tx.encode_hex())
            })?;

        // get the staker's signature on the unbonding tx
        let staker_sig = k256::schnorr::Signature::try_from(sig.as_slice())
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

        // Verify the signature
        babylon_btcstaking::sig_verify::verify_transaction_sig_with_output(
            &unbonding_tx,
            staking_output,
            unbonding_path_script.as_script(),
            &staker_pk,
            &staker_sig,
        )
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
    }

    // make static analyser happy with unused parameters
    #[cfg(not(feature = "full-validation"))]
    let _ = (height, undelegation);

    Ok(())
}

pub fn verify_slashed_delegation(
    height: u64,
    delegation: &SlashedBtcDelegation,
) -> Result<(), ContractError> {
    // The following code is marked with `#[cfg(feature = "full-validation")]`
    // so that it is included in the build if the `full-validation` feature is
    // enabled.
    // TODO: fix contract size when full-validation is enabled
    #[cfg(feature = "full-validation")]
    {
        // TODO: check if the SK corresponds to a FP PK that the delegation restakes to
    }

    // make static analyser happy with unused parameters
    #[cfg(not(feature = "full-validation"))]
    let _ = (height, delegation);

    Ok(())
}
