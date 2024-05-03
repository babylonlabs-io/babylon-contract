use bitcoin::XOnlyPublicKey;
use bitcoin::{address::Address, network::Network, Transaction};
use rust_decimal::{prelude::*, Decimal};

use crate::scripts_utils;

/// Checks if a transaction has exactly one input and one output.
fn is_transfer_tx(tx: &Transaction) -> Result<(), String> {
    if tx.input.len() != 1 {
        return Err("Transfer transaction must have exactly one input.".into());
    }

    if tx.output.len() != 1 {
        return Err("Transfer transaction must have exactly one output.".into());
    }

    Ok(())
}

/// Checks if a transaction is a simple transfer, meaning it has exactly one input and one output,
/// is not replaceable (sequence number is max), and has no locktime.
#[allow(dead_code)]
fn is_simple_transfer(tx: &Transaction) -> Result<(), String> {
    is_transfer_tx(tx)?; // Reuse the is_transfer_tx check and propagate error if any

    if !tx.input[0].sequence.is_rbf() {
        return Err("Simple transfer transaction must not be replaceable.".into());
    }

    if tx.lock_time.to_consensus_u32() > 0 {
        return Err("Simple transfer transaction must not have locktime.".into());
    }

    Ok(())
}

/// Validates a slashing transaction with strict criteria
#[allow(clippy::too_many_arguments)]
fn validate_slashing_tx(
    slashing_tx: &Transaction,
    slashing_address: &Address,
    slashing_rate: f64,
    slashing_tx_min_fee: u64,
    staking_output_value: u64,
    staker_pk: &XOnlyPublicKey,
    slashing_change_lock_time: u16,
    network: Network,
) -> Result<(), String> {
    if slashing_tx.input.len() != 1 {
        return Err("Slashing transaction must have exactly one input".into());
    }

    if slashing_tx.input[0].sequence.is_rbf() {
        return Err("Simple transfer transaction must not be replaceable.".into());
    }

    if slashing_tx.lock_time.to_consensus_u32() > 0 {
        return Err("Simple transfer transaction must not have locktime.".into());
    }

    if slashing_tx.output.len() != 2 {
        return Err("Slashing transaction must have exactly 2 outputs".into());
    }

    let expected_slashing_amount = (staking_output_value as f64 * slashing_rate).round() as u64;
    if slashing_tx.output[0].value.to_sat() < expected_slashing_amount {
        return Err(format!(
            "Slashing transaction must slash at least {} satoshis",
            expected_slashing_amount
        ));
    }

    // Verify that the first output pays to the provided slashing address.
    let slashing_pk_script = slashing_address.script_pubkey();
    if slashing_tx.output[0].script_pubkey != slashing_pk_script {
        return Err("Slashing transaction must pay to the provided slashing address".into());
    }

    // Verify that the second output pays to the taproot address which locks funds for
    // slashingChangeLockTime
    // Build script based on the timelock details
    let expected_pk_script = scripts_utils::build_relative_time_lock_pk_script(
        staker_pk,
        slashing_change_lock_time,
        network,
    )?;
    if slashing_tx.output[1].script_pubkey.ne(&expected_pk_script) {
        return Err("Invalid slashing tx change output script".into());
    }

    // Check for dust outputs
    if slashing_tx
        .output
        .iter()
        .any(|out| out.value.to_sat() <= 546)
    {
        return Err("Transaction contains dust outputs".into());
    }

    // Check fees
    let total_output_value: u64 = slashing_tx
        .output
        .iter()
        .map(|out| out.value.to_sat())
        .sum();
    if staking_output_value <= total_output_value {
        return Err("Slashing transaction must not spend more than the staking transaction".into());
    }

    let calculated_fee = staking_output_value - total_output_value;
    if calculated_fee < slashing_tx_min_fee {
        return Err(format!(
            "Slashing transaction fee must be larger than {}",
            slashing_tx_min_fee
        ));
    }

    Ok(())
}

/// Checks if the given rate is between the valid range i.e., (0,1) with a precision of at most 2 decimal places.
fn is_rate_valid(rate: f64) -> bool {
    // Check if the slashing rate is between 0 and 1
    if rate <= 0.0 || rate >= 1.0 {
        return false;
    }

    // Multiply by 100 to move the decimal places and check if precision is at most 2 decimal places
    let multiplied_rate = Decimal::from_f64(rate * 100.0).unwrap();

    // Truncate the rate to remove decimal places
    let truncated_rate = multiplied_rate.trunc();

    // Check if the truncated rate is equal to the original rate
    multiplied_rate == truncated_rate
}

/// Validates all relevant data of slashing and funding transactions.
#[allow(clippy::too_many_arguments)]
pub fn check_transactions(
    slashing_tx: &Transaction,
    funding_transaction: &Transaction,
    funding_output_idx: u32,
    slashing_tx_min_fee: u64,
    slashing_rate: f64,
    slashing_address: &Address,
    staker_pk: &XOnlyPublicKey,
    slashing_change_lock_time: u16,
    network: Network,
) -> Result<(), String> {
    // Check if slashing tx min fee is valid
    if slashing_tx_min_fee == 0 {
        return Err("Slashing transaction min fee must be larger than 0".into());
    }

    // Check if slashing rate is in the valid range (0,1)
    if !is_rate_valid(slashing_rate) {
        return Err("Invalid slashing rate".into());
    }

    if funding_output_idx >= funding_transaction.output.len() as u32 {
        return Err(format!(
            "Invalid funding output index {}, tx has {} outputs",
            funding_output_idx,
            funding_transaction.output.len()
        ));
    }

    let staking_output = &funding_transaction.output[funding_output_idx as usize];

    // Check if slashing transaction is valid
    validate_slashing_tx(
        slashing_tx,
        slashing_address,
        slashing_rate,
        slashing_tx_min_fee,
        staking_output.value.to_sat(),
        staker_pk,
        slashing_change_lock_time,
        network,
    )?;

    // Check that slashing transaction input is pointing to staking transaction
    let staking_tx_hash = funding_transaction.txid(); // Hash of the funding transaction
    if slashing_tx.input[0]
        .previous_output
        .txid
        .ne(&staking_tx_hash)
    {
        return Err("Slashing transaction must spend staking output".into());
    }

    // Check that index of the funding output matches index of the input in slashing transaction
    if slashing_tx.input[0].previous_output.vout != funding_output_idx {
        return Err("Slashing transaction input must spend staking output".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use self::scripts_utils::BabylonScriptPaths;
    use super::*;
    use crate::sig_verify::{
        enc_verify_transaction_sig_with_output, new_adaptor_sig, verify_transaction_sig_with_output,
    };
    use babylon_proto::babylon::btcstaking::v1::{BtcDelegation, Params};
    use bitcoin::address::Address;
    use bitcoin::consensus::deserialize;
    use bitcoin::secp256k1::schnorr::Signature;
    use bitcoin::{Transaction, XOnlyPublicKey};
    use prost::Message;

    use std::fs;

    const PARAMS_DATA: &str = "./testdata/btcstaking_params.dat";
    const BTC_DELEGATION_DATA: &str = "./testdata/btc_delegation.dat";

    pub(crate) fn get_params() -> Params {
        let testdata: &[u8] = &fs::read(PARAMS_DATA).unwrap();

        Params::decode(testdata).unwrap()
    }

    pub(crate) fn get_btc_delegation() -> BtcDelegation {
        let testdata: &[u8] = &fs::read(BTC_DELEGATION_DATA).unwrap();

        BtcDelegation::decode(testdata).unwrap()
    }

    #[test]
    fn test_check_transactions() {
        let params = get_params();
        let btc_del = get_btc_delegation();

        let staking_tx: Transaction = deserialize(&btc_del.staking_tx).unwrap();
        let slashing_tx: Transaction = deserialize(&btc_del.slashing_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let slashing_tx_min_fee: u64 = 1;
        let slashing_rate: f64 = 0.01;
        let slashing_address: Address = Address::from_str(&params.slashing_address)
            .unwrap()
            .assume_checked();
        let staker_pk: XOnlyPublicKey = XOnlyPublicKey::from_slice(&btc_del.btc_pk).unwrap();
        let slashing_change_lock_time: u16 = 101;
        let network: Network = Network::Regtest;

        // test check_transactions
        check_transactions(
            &slashing_tx,
            &staking_tx,
            funding_out_idx,
            slashing_tx_min_fee,
            slashing_rate,
            &slashing_address,
            &staker_pk,
            slashing_change_lock_time,
            network,
        )
        .unwrap();
    }

    #[test]
    fn test_verify_unbonding_tx_schnorr_sig() {
        let params = get_params();
        let btc_del = get_btc_delegation();

        let staking_tx: Transaction = deserialize(&btc_del.staking_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let staker_pk: XOnlyPublicKey = XOnlyPublicKey::from_slice(&btc_del.btc_pk).unwrap();

        let fp_pks: Vec<XOnlyPublicKey> = btc_del
            .fp_btc_pk_list
            .iter()
            .map(|bytes| XOnlyPublicKey::from_slice(bytes).expect("Invalid public key bytes"))
            .collect();
        let cov_pks: Vec<XOnlyPublicKey> = params
            .covenant_pks
            .iter()
            .map(|bytes| XOnlyPublicKey::from_slice(bytes).expect("Invalid public key bytes"))
            .collect();

        let babylon_script_paths = BabylonScriptPaths::new(
            &staker_pk,
            &fp_pks,
            &cov_pks,
            params.covenant_quorum as usize,
            5, // TODO: parameterise
        )
        .unwrap();

        // test verifying Schnorr signature, i.e., covenant signatures over unbonding tx
        let btc_undel_info = &btc_del.btc_undelegation.unwrap();
        let unbonding_tx: Transaction = deserialize(&btc_undel_info.unbonding_tx).unwrap();
        let staking_out = &staking_tx.output[funding_out_idx as usize];
        let unbonding_pk_script = babylon_script_paths.unbonding_path_script;
        for cov_unbonding_tx_sig_info in &btc_undel_info.covenant_unbonding_sig_list {
            let cov_pk = XOnlyPublicKey::from_slice(&cov_unbonding_tx_sig_info.pk).unwrap();
            let cov_sig = Signature::from_slice(&cov_unbonding_tx_sig_info.sig).unwrap();
            verify_transaction_sig_with_output(
                &unbonding_tx,
                staking_out,
                unbonding_pk_script.as_script(),
                &cov_pk,
                &cov_sig,
            )
            .unwrap();
        }
    }

    #[test]
    fn test_verify_slashing_tx_adaptor_sig() {
        let params = get_params();
        let btc_del = get_btc_delegation();

        let staking_tx: Transaction = deserialize(&btc_del.staking_tx).unwrap();
        let slashing_tx: Transaction = deserialize(&btc_del.slashing_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let staker_pk: XOnlyPublicKey = XOnlyPublicKey::from_slice(&btc_del.btc_pk).unwrap();
        let staking_out = &staking_tx.output[funding_out_idx as usize];

        let fp_pks: Vec<XOnlyPublicKey> = btc_del
            .fp_btc_pk_list
            .iter()
            .map(|bytes| XOnlyPublicKey::from_slice(bytes).expect("Invalid public key bytes"))
            .collect();
        let cov_pks: Vec<XOnlyPublicKey> = params
            .covenant_pks
            .iter()
            .map(|bytes| XOnlyPublicKey::from_slice(bytes).expect("Invalid public key bytes"))
            .collect();

        let babylon_script_paths = BabylonScriptPaths::new(
            &staker_pk,
            &fp_pks,
            &cov_pks,
            params.covenant_quorum as usize,
            5, // TODO: parameterise
        )
        .unwrap();

        // test verifying adaptor signature, i.e., covenant signatures over slashing tx
        for cov_slashing_tx_info in btc_del.covenant_sigs {
            let cov_pk = XOnlyPublicKey::from_slice(&cov_slashing_tx_info.cov_pk).unwrap();
            for (idx, cov_asig_bytes) in cov_slashing_tx_info.adaptor_sigs.iter().enumerate() {
                let cov_asig = new_adaptor_sig(cov_asig_bytes).unwrap();
                enc_verify_transaction_sig_with_output(
                    &slashing_tx,
                    staking_out,
                    babylon_script_paths.slashing_path_script.as_script(),
                    &cov_pk,
                    &fp_pks[idx],
                    &cov_asig,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn test_verify_unbonding_slashing_tx_adaptor_sig() {
        let params = get_params();
        let btc_del = get_btc_delegation();
        let btc_undel = btc_del.btc_undelegation.unwrap();
        let unbonding_tx: Transaction = deserialize(&btc_undel.unbonding_tx).unwrap();
        let unbonding_slashing_tx: Transaction = deserialize(&btc_undel.slashing_tx).unwrap();

        let funding_out_idx: u32 = 0;
        let staker_pk: XOnlyPublicKey = XOnlyPublicKey::from_slice(&btc_del.btc_pk).unwrap();
        let unbonding_out = &unbonding_tx.output[funding_out_idx as usize];

        let fp_pks: Vec<XOnlyPublicKey> = btc_del
            .fp_btc_pk_list
            .iter()
            .map(|bytes| XOnlyPublicKey::from_slice(bytes).expect("Invalid public key bytes"))
            .collect();
        let cov_pks: Vec<XOnlyPublicKey> = params
            .covenant_pks
            .iter()
            .map(|bytes| XOnlyPublicKey::from_slice(bytes).expect("Invalid public key bytes"))
            .collect();

        let babylon_unbonding_script_paths = BabylonScriptPaths::new(
            &staker_pk,
            &fp_pks,
            &cov_pks,
            params.covenant_quorum as usize,
            101, // TODO: parameterise
        )
        .unwrap();

        // test verifying adaptor signature, i.e., covenant signatures over slashing tx
        for cov_unbonding_slashing_tx_info in btc_undel.covenant_slashing_sigs {
            let cov_pk =
                XOnlyPublicKey::from_slice(&cov_unbonding_slashing_tx_info.cov_pk).unwrap();
            for (idx, cov_asig_bytes) in cov_unbonding_slashing_tx_info
                .adaptor_sigs
                .iter()
                .enumerate()
            {
                let cov_asig = new_adaptor_sig(cov_asig_bytes).unwrap();
                enc_verify_transaction_sig_with_output(
                    &unbonding_slashing_tx,
                    unbonding_out,
                    babylon_unbonding_script_paths
                        .slashing_path_script
                        .as_script(),
                    &cov_pk,
                    &fp_pks[idx],
                    &cov_asig,
                )
                .unwrap();
            }
        }
    }
}
