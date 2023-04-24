use babylon_bitcoin::BlockHeader;
use babylon_bitcoin::Uint256;
use babylon_proto::babylon::btccheckpoint::v1::TransactionInfo;
use babylon_proto::babylon::checkpointing::v1::RawCheckpoint;
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::ProofEpochSealed;
use core::panic;
use prost::Message;

pub const NUM_BTC_TXS: usize = 2;

/// verify_epoch_sealed ensures the given raw checkpoint is sealed, i.e., BLS-signed,
/// by the validator set of the given epoch
/// reference implementation: https://github.com/babylonchain/babylon/blob/v0.5.0/x/zoneconcierge/keeper/proof_epoch_sealed.go
pub fn verify_epoch_sealed(
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof: &ProofEpochSealed,
) -> Result<(), String> {
    // ensure epoch number is same in epoch and raw checkpoint
    if epoch.epoch_number != raw_ckpt.epoch_num {
        return Err(format!(
            "epoch's epoch number ({}) is not equal to raw_ckpt's epoch number ({})",
            epoch.epoch_number, raw_ckpt.epoch_num
        ));
    }

    // ensure the raw checkpoint's last_commit_hash is same as in the header of the sealer header
    // NOTE: since this proof is assembled by a Babylon node who has verified the checkpoint,
    // the two lch values should always be the same, otherwise this Babylon node is malicious.
    // This is different from the checkpoint verification rules in checkpointing,
    // where a checkpoint with valid BLS multisig but different lch signals a dishonest majority equivocation.
    let lch_in_ckpt: &[u8] = raw_ckpt.last_commit_hash.as_ref();
    let sealer_header_res = epoch.sealer_header.as_ref();
    if sealer_header_res.is_none() {
        return Err("epoch's sealer_header is empty".to_string());
    }
    let sealer_header = sealer_header_res.unwrap();
    let lch_in_sealer_header: &[u8] = &sealer_header.last_commit_hash;
    if !lch_in_ckpt.eq(lch_in_sealer_header) {
        return Err(format!("checkpoint's last_commit_hash ({}) is not equal to sealer header's last_commit_hash ({})", hex::encode(lch_in_ckpt), hex::encode(lch_in_sealer_header)));
    }

    /*
        Ensure more than 1/3 (in voting power) validators of this epoch have
        signed (epoch_num || last_commit_hash) in the raw checkpoint
    */
    let val_set = babylon_proto::babylon::checkpointing::v1::ValidatorWithBlsKeySet {
        val_set: proof.validator_set.clone(),
    };
    let subset_res = val_set.find_subset_with_power_sum(&raw_ckpt.bitmap);
    if subset_res.is_err() {
        return Err(format!("failed to get voted subset: {:?}", subset_res));
    }
    let (signer_set, signer_set_power) = subset_res.unwrap();
    let threshold = val_set.get_total_power() / 3;
    // ensure the signerSet has > 1/3 voting power
    if signer_set_power <= threshold {
        return Err("the BLS signature involves insufficient voting power".to_string());
    }
    // verify BLS multisig
    super::bls::verify_multisig(&raw_ckpt.bls_multi_sig, &signer_set, &raw_ckpt.signed_msg())?;

    // Ensure The epoch medatata is committed to the app_hash of the sealer header
    let root = &sealer_header.app_hash;
    let epoch_info_key = super::cosmos_store::get_epoch_info_key(epoch.epoch_number);
    let epoch_bytes = epoch.encode_to_vec();
    let epoch_merkle_proof = proof.proof_epoch_info.clone().unwrap();
    super::cosmos_store::verify_store(
        root,
        super::cosmos_store::EPOCHING_STORE_KEY,
        &epoch_info_key,
        &epoch_bytes,
        epoch_merkle_proof,
    )?;

    // Ensure The validator set is committed to the app_hash of the sealer header
    let valset_key = super::cosmos_store::get_valset_key(epoch.epoch_number);
    let valset_bytes = val_set.encode_to_vec();
    let valset_merkle_proof = proof.proof_epoch_val_set.clone().unwrap();
    super::cosmos_store::verify_store(
        root,
        super::cosmos_store::CHECKPOINTING_STORE_KEY,
        &valset_key,
        &valset_bytes,
        valset_merkle_proof,
    )?;

    Ok(())
}

/// verify_checkpoint_submitted ensures the given raw checkpoint is submitted, i.e.,
/// whose two txs are in the given 2 BTC headers.
/// reference implementation: https://github.com/babylonchain/babylon/blob/v0.5.0/x/zoneconcierge/keeper/proof_epoch_submitted.go
pub fn verify_checkpoint_submitted(
    raw_ckpt: &RawCheckpoint,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
    btc_headers: &[BlockHeader; NUM_BTC_TXS],
    pow_limit: &Uint256,
    babylon_tag: &[u8],
) -> Result<(), String> {
    panic!("TODO: implement me")
}

#[cfg(test)]
mod tests {
    use super::*;
    use babylon_proto::babylon::zoneconcierge::v1::QueryFinalizedChainInfoResponse;
    use std::fs;

    const TESTDATA: &str = "./testdata/finalized_chain_info.dat";

    #[test]
    fn verify_epoch_sealed_works() {
        let testdata: &[u8] = &fs::read(TESTDATA).unwrap();
        let finalized_chain_info_resp = QueryFinalizedChainInfoResponse::decode(testdata).unwrap();
        let epoch = finalized_chain_info_resp.epoch_info.unwrap();
        let raw_ckpt = finalized_chain_info_resp.raw_checkpoint.unwrap();
        let proof = finalized_chain_info_resp
            .proof
            .unwrap()
            .proof_epoch_sealed
            .unwrap();
        // TODO: test does not work due to the bug of ProveEpochSealed in the testnet
        // will uncomment after getting valid testdata
        // verify_epoch_sealed(&epoch, &raw_ckpt, &proof).unwrap();
    }

    // TODO: more tests on different scenarios, e.g., random number of headers and conflicted headers
}
