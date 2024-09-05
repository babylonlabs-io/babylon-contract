use crate::error::Error;
use crate::scripts_utils;
use crate::Result;

use bitcoin::{address::Address, Transaction};
use k256::schnorr::VerifyingKey;
use rust_decimal::{prelude::*, Decimal};

/// Checks if a transaction has exactly one input and one output.
fn is_transfer_tx(tx: &Transaction) -> Result<()> {
    if tx.input.len() != 1 {
        return Err(Error::TxInputCountMismatch(1, tx.input.len()));
    }

    if tx.output.len() != 1 {
        return Err(Error::TxOutputCountMismatch(1, tx.output.len()));
    }

    Ok(())
}

/// Checks if a transaction is a simple transfer, meaning it has exactly one input and one output,
/// is not replaceable (sequence number is max), and has no locktime.
#[allow(dead_code)]
fn is_simple_transfer(tx: &Transaction) -> Result<()> {
    is_transfer_tx(tx)?; // Reuse the is_transfer_tx check and propagate error if any

    if !tx.input[0].sequence.is_rbf() {
        return Err(Error::TxIsReplaceable {});
    }

    if tx.lock_time.to_consensus_u32() > 0 {
        return Err(Error::TxHasLocktime {});
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
    staker_pk: &VerifyingKey,
    slashing_change_lock_time: u16,
) -> Result<()> {
    if slashing_tx.input.len() != 1 {
        return Err(Error::TxInputCountMismatch(1, slashing_tx.input.len()));
    }

    if slashing_tx.input[0].sequence.is_rbf() {
        return Err(Error::TxIsReplaceable {});
    }

    if slashing_tx.lock_time.to_consensus_u32() > 0 {
        return Err(Error::TxHasLocktime {});
    }

    if slashing_tx.output.len() != 2 {
        return Err(Error::TxOutputCountMismatch(2, slashing_tx.output.len()));
    }

    let expected_slashing_amount = (staking_output_value as f64 * slashing_rate).round() as u64;
    if slashing_tx.output[0].value.to_sat() < expected_slashing_amount {
        return Err(Error::InsufficientSlashingAmount(expected_slashing_amount));
    }

    // Verify that the first output pays to the provided slashing address.
    let slashing_pk_script = slashing_address.script_pubkey();
    if slashing_tx.output[0].script_pubkey != slashing_pk_script {
        return Err(Error::InvalidSlashingAddress {});
    }

    // Verify that the second output pays to the taproot address which locks funds for
    // slashingChangeLockTime
    // Build script based on the timelock details
    let expected_pk_script =
        scripts_utils::build_relative_time_lock_pk_script(staker_pk, slashing_change_lock_time)?;
    if slashing_tx.output[1].script_pubkey.ne(&expected_pk_script) {
        println!("expected_pk_script: {:?}", expected_pk_script);
        println!(
            "slashing_tx.output[1].script_pubkey: {:?}",
            slashing_tx.output[1].script_pubkey
        );
        return Err(Error::InvalidSlashingTxChangeOutputScript {});
    }

    // Check for dust outputs
    if slashing_tx
        .output
        .iter()
        .any(|out| out.value.to_sat() <= 546)
    {
        return Err(Error::TxContainsDustOutputs {});
    }

    // Check fees
    let total_output_value: u64 = slashing_tx
        .output
        .iter()
        .map(|out| out.value.to_sat())
        .sum();
    if staking_output_value <= total_output_value {
        return Err(Error::SlashingTxOverspend {});
    }

    let calculated_fee = staking_output_value - total_output_value;
    if calculated_fee < slashing_tx_min_fee {
        return Err(Error::InsufficientSlashingFee(slashing_tx_min_fee));
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
    staker_pk: &VerifyingKey,
    slashing_change_lock_time: u16,
) -> Result<()> {
    // Check if slashing tx min fee is valid
    if slashing_tx_min_fee == 0 {
        return Err(Error::InsufficientSlashingFee(0));
    }

    // Check if slashing rate is in the valid range (0,1)
    if !is_rate_valid(slashing_rate) {
        return Err(Error::InvalidSlashingRate {});
    }

    if funding_output_idx >= funding_transaction.output.len() as u32 {
        return Err(Error::InvalidFundingOutputIndex(
            funding_output_idx,
            funding_transaction.output.len(),
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
    )?;

    // Check that slashing transaction input is pointing to staking transaction
    let staking_tx_hash = funding_transaction.txid(); // Hash of the funding transaction
    if slashing_tx.input[0]
        .previous_output
        .txid
        .ne(&staking_tx_hash)
    {
        return Err(Error::StakingOutputNotSpentBySlashingTx {});
    }

    // Check that index of the funding output matches index of the input in slashing transaction
    if slashing_tx.input[0].previous_output.vout != funding_output_idx {
        return Err(Error::StakingOutputNotSpentBySlashingTx {});
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use self::scripts_utils::BabylonScriptPaths;
    use super::*;
    use crate::adaptor_sig::AdaptorSignature;
    use crate::sig_verify::{
        enc_verify_transaction_sig_with_output, verify_transaction_sig_with_output,
    };
    use bitcoin::address::Address;
    use bitcoin::consensus::deserialize;

    use test_utils::{get_btc_delegation, get_params};

    #[test]
    fn test_check_transactions() {
        let btc_del = get_btc_delegation(1, vec![1]);
        let params = get_params();

        let staking_tx: Transaction = deserialize(&btc_del.staking_tx).unwrap();
        let slashing_tx: Transaction = deserialize(&btc_del.slashing_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let slashing_tx_min_fee: u64 = 1;
        let slashing_rate: f64 = 0.01;
        let slashing_address: Address = Address::from_str(&params.slashing_address)
            .unwrap()
            .assume_checked();
        let staker_pk: VerifyingKey = VerifyingKey::from_bytes(&btc_del.btc_pk).unwrap();
        let slashing_change_lock_time: u16 = 101;

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
        )
        .unwrap();
    }

    #[test]
    fn test_verify_unbonding_tx_schnorr_sig() {
        let btc_del = get_btc_delegation(1, vec![1]);
        let params = get_params();

        let staking_tx: Transaction = deserialize(&btc_del.staking_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let staker_pk: VerifyingKey = VerifyingKey::from_bytes(&btc_del.btc_pk).unwrap();

        let fp_pks: Vec<VerifyingKey> = btc_del
            .fp_btc_pk_list
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
            .collect();
        let cov_pks: Vec<VerifyingKey> = params
            .covenant_pks
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
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
            let cov_pk = VerifyingKey::from_bytes(&cov_unbonding_tx_sig_info.pk).unwrap();

            let cov_sig =
                k256::schnorr::Signature::try_from(&cov_unbonding_tx_sig_info.sig[..]).unwrap();
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
        let btc_del = get_btc_delegation(1, vec![1]);
        let params = get_params();

        let staking_tx: Transaction = deserialize(&btc_del.staking_tx).unwrap();
        let slashing_tx: Transaction = deserialize(&btc_del.slashing_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let staker_pk: VerifyingKey = VerifyingKey::from_bytes(&btc_del.btc_pk).unwrap();
        let staking_out = &staking_tx.output[funding_out_idx as usize];

        let fp_pks: Vec<VerifyingKey> = btc_del
            .fp_btc_pk_list
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
            .collect();
        let cov_pks: Vec<VerifyingKey> = params
            .covenant_pks
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
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
            let cov_pk = VerifyingKey::from_bytes(&cov_slashing_tx_info.cov_pk).unwrap();
            for (idx, cov_asig_bytes) in cov_slashing_tx_info.adaptor_sigs.iter().enumerate() {
                let cov_asig = AdaptorSignature::new(cov_asig_bytes).unwrap();
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
        let btc_del = get_btc_delegation(1, vec![1]);
        let params = get_params();

        let btc_undel = btc_del.btc_undelegation.unwrap();
        let unbonding_tx: Transaction = deserialize(&btc_undel.unbonding_tx).unwrap();
        let unbonding_slashing_tx: Transaction = deserialize(&btc_undel.slashing_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let staker_pk: VerifyingKey = VerifyingKey::from_bytes(&btc_del.btc_pk).unwrap();
        let unbonding_out = &unbonding_tx.output[funding_out_idx as usize];

        let fp_pks: Vec<VerifyingKey> = btc_del
            .fp_btc_pk_list
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
            .collect();
        let cov_pks: Vec<VerifyingKey> = params
            .covenant_pks
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
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
            let cov_pk = VerifyingKey::from_bytes(&cov_unbonding_slashing_tx_info.cov_pk).unwrap();
            for (idx, cov_asig_bytes) in cov_unbonding_slashing_tx_info
                .adaptor_sigs
                .iter()
                .enumerate()
            {
                let cov_asig = AdaptorSignature::new(cov_asig_bytes).unwrap();
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
