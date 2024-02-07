//! babylon_epoch_chain is the storage for the chain of **finalised** Babylon epochs.
//! It maintains a chain of finalised Babylon epochs.
//! NOTE: the Babylon epoch chain is always finalised, i.e., w-deep on BTC.
use babylon_bitcoin::BlockHeader;
use hex::ToHex;
use prost::Message;

use cosmwasm_std::{StdError, StdResult, Storage};
use cw_storage_plus::{Item, Map};

use babylon_proto::babylon::btccheckpoint::v1::TransactionInfo;
use babylon_proto::babylon::checkpointing::v1::RawCheckpoint;
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::{BtcTimestamp, ProofEpochSealed};

use crate::error::BabylonEpochChainError;
use crate::state::config::CONFIG;
use crate::utils::babylon_epoch_chain::{
    verify_checkpoint_submitted, verify_epoch_sealed, NUM_BTC_TXS,
};

pub const BABYLON_EPOCHS: Map<u64, Vec<u8>> = Map::new("babylon_epochs");
pub const BABYLON_EPOCH_BASE: Item<Vec<u8>> = Item::new("babylon_epoch_base");
pub const BABYLON_EPOCH_EPOCH_LAST_FINALIZED: Item<Vec<u8>> = Item::new("babylon_epoch_last");
pub const BABYLON_CHECKPOINTS: Map<u64, Vec<u8>> = Map::new("babylon_checkpoints");

// is_initialized checks if the BTC light client has been initialised or not
// the check is done by checking existence of base epoch
pub fn is_initialized(storage: &mut dyn Storage) -> bool {
    BABYLON_EPOCH_BASE.load(storage).is_ok()
}

// getter/setter for base epoch
pub fn get_base_epoch(storage: &dyn Storage) -> Result<Epoch, BabylonEpochChainError> {
    // NOTE: if init is successful, then base epoch is guaranteed to be in storage and decodable
    let base_epoch_bytes = BABYLON_EPOCH_BASE.load(storage)?;

    Epoch::decode(base_epoch_bytes.as_slice()).map_err(BabylonEpochChainError::DecodeError)
}

fn set_base_epoch(storage: &mut dyn Storage, base_epoch: &Epoch) -> StdResult<()> {
    let base_epoch_bytes = &base_epoch.encode_to_vec();
    BABYLON_EPOCH_BASE.save(storage, base_epoch_bytes)
}

// getter/setter for last finalised epoch
pub fn get_last_finalized_epoch(storage: &dyn Storage) -> Result<Epoch, BabylonEpochChainError> {
    let last_finalized_epoch_bytes = BABYLON_EPOCH_EPOCH_LAST_FINALIZED
        .load(storage)
        .map_err(|_| BabylonEpochChainError::NoFinalizedEpoch {})?;
    Epoch::decode(last_finalized_epoch_bytes.as_slice())
        .map_err(BabylonEpochChainError::DecodeError)
}

fn set_last_finalized_epoch(
    storage: &mut dyn Storage,
    last_finalized_epoch: &Epoch,
) -> StdResult<()> {
    let last_finalized_epoch_bytes = &last_finalized_epoch.encode_to_vec();
    BABYLON_EPOCH_EPOCH_LAST_FINALIZED.save(storage, last_finalized_epoch_bytes)
}

/// get_epoch retrieves the metadata of a given epoch
pub fn get_epoch(
    storage: &dyn Storage,
    epoch_number: u64,
) -> Result<Epoch, BabylonEpochChainError> {
    // try to find the epoch metadata of the given epoch
    let epoch_bytes = BABYLON_EPOCHS
        .load(storage, epoch_number)
        .map_err(|_| BabylonEpochChainError::EpochNotFoundError { epoch_number })?;

    // try to decode the epoch
    let epoch = Epoch::decode(epoch_bytes.as_slice())?;

    Ok(epoch)
}

/// get_checkpoint retrieves the checkpoint of a given epoch
pub fn get_checkpoint(
    storage: &dyn Storage,
    epoch_number: u64,
) -> Result<RawCheckpoint, BabylonEpochChainError> {
    // try to find the checkpoint of the given epoch
    let ckpt_bytes = BABYLON_CHECKPOINTS
        .load(storage, epoch_number)
        .map_err(|_| BabylonEpochChainError::CheckpointNotFoundError { epoch_number })?;

    // try to decode the checkpoint
    let ckpt_res = RawCheckpoint::decode(ckpt_bytes.as_slice())?;

    Ok(ckpt_res)
}

struct VerifiedEpochAndCheckpoint {
    pub epoch: Epoch,
    pub raw_ckpt: RawCheckpoint,
}

/// verify_epoch_and_checkpoint verifies an epoch metadata and a raw checkpoint
/// The verifications include:
/// - whether the raw checkpoint is BTC-finalised, i.e., in a w-deep BTC header
/// - whether the epoch is sealed by the validator set of this epoch
fn verify_epoch_and_checkpoint(
    storage: &mut dyn Storage,
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof_epoch_sealed: &ProofEpochSealed,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
) -> Result<VerifiedEpochAndCheckpoint, BabylonEpochChainError> {
    let cfg = CONFIG.load(storage)?;

    // ensure that raw_ckpt is corresponding to the epoch
    if epoch.epoch_number != raw_ckpt.epoch_num {
        return Err(BabylonEpochChainError::CheckpointNotMatchError {
            ckpt_epoch_number: raw_ckpt.epoch_num,
            epoch_number: epoch.epoch_number,
        });
    }

    // get BTC headers from local BTC light client
    let btc_headers: [BlockHeader; NUM_BTC_TXS] = txs_info
        .iter()
        .map(|tx_info| {
            let tx_key = tx_info
                .key
                .clone()
                .ok_or(BabylonEpochChainError::EmptyTxKey {})?;
            let btc_header_hash = &tx_key.hash;
            let btc_header_info = super::btc_light_client::get_header(storage, btc_header_hash)
                .map_err(|_| BabylonEpochChainError::BTCHeaderNotFoundError {
                    hash: hex::encode(btc_header_hash),
                })?;
            let btc_header: BlockHeader = babylon_bitcoin::deserialize(&btc_header_info.header)
                .map_err(|_| BabylonEpochChainError::BTCHeaderDecodeError {})?;
            Ok(btc_header)
        })
        .collect::<Result<Vec<BlockHeader>, BabylonEpochChainError>>()?
        .try_into()
        .map_err(|_| BabylonEpochChainError::BTCHeaderDecodeError {})?;

    // this will be used for checking w-deep later
    let mut min_height: u64 = u64::MAX;

    // ensure the given btc headers are in BTC light clients
    for btc_header in btc_headers.iter() {
        let hash = btc_header.block_hash();
        let header = super::btc_light_client::get_header(storage, &hash).map_err(|_| {
            BabylonEpochChainError::BTCHeaderNotFoundError {
                hash: hash.encode_hex(),
            }
        })?;
        // refresh min_height
        let header_height = header.height;
        if min_height > header_height {
            min_height = header_height;
        }
    }

    // ensure at least 1 given btc headers are finalised, i.e., w-deep
    let tip_height = super::btc_light_client::get_tip(storage)?.height;
    if min_height + cfg.checkpoint_finalization_timeout > tip_height {
        return Err(BabylonEpochChainError::BTCHeaderNotDeepEnough {
            w: cfg.checkpoint_finalization_timeout,
        });
    }

    // verify the checkpoint is submitted, i.e., committed to the 2 BTC headers
    verify_checkpoint_submitted(raw_ckpt, txs_info, &btc_headers, &cfg.babylon_tag)
        .map_err(|e| BabylonEpochChainError::CheckpointNotSubmitted { err_msg: e })?;

    // verify the epoch is sealed by its validator set
    verify_epoch_sealed(epoch, raw_ckpt, proof_epoch_sealed)
        .map_err(|e| BabylonEpochChainError::EpochNotSealed { err_msg: e })?;

    // all good
    Ok(VerifiedEpochAndCheckpoint {
        epoch: epoch.clone(),
        raw_ckpt: raw_ckpt.clone(),
    })
}

/// insert_epoch_and_checkpoint inserts an epoch and the corresponding raw checkpoint, and
/// update the last finalised checkpoint
/// NOTE: epoch/raw_ckpt have already passed all verifications
fn insert_epoch_and_checkpoint(
    storage: &mut dyn Storage,
    verified_tuple: &VerifiedEpochAndCheckpoint,
) -> StdResult<()> {
    // insert epoch metadata
    let epoch_number = verified_tuple.epoch.epoch_number;
    let epoch_bytes = verified_tuple.epoch.encode_to_vec();
    BABYLON_EPOCHS.save(storage, epoch_number, &epoch_bytes)?;

    // insert raw ckpt
    let raw_ckpt_bytes = verified_tuple.raw_ckpt.encode_to_vec();
    BABYLON_CHECKPOINTS.save(storage, epoch_number, &raw_ckpt_bytes)?;

    // update last finalised epoch
    set_last_finalized_epoch(storage, &verified_tuple.epoch)
}

/// extract_data_from_btc_ts extracts data needed for verifying Babylon epoch chain
/// from a given BTC timestamp
pub fn extract_data_from_btc_ts(
    btc_ts: &BtcTimestamp,
) -> Result<
    (
        &Epoch,
        &RawCheckpoint,
        &ProofEpochSealed,
        [TransactionInfo; NUM_BTC_TXS],
    ),
    StdError,
> {
    let epoch = btc_ts
        .epoch_info
        .as_ref()
        .ok_or(StdError::generic_err("empty epoch info"))?;
    let raw_ckpt = btc_ts
        .raw_checkpoint
        .as_ref()
        .ok_or(StdError::generic_err("empty raw checkpoint"))?;
    let proof = btc_ts
        .proof
        .as_ref()
        .ok_or(StdError::generic_err("empty proof"))?;
    let proof_epoch_sealed = proof
        .proof_epoch_sealed
        .as_ref()
        .ok_or(StdError::generic_err("empty proof_epoch_sealed"))?;
    let txs_info: [TransactionInfo; NUM_BTC_TXS] = proof
        .proof_epoch_submitted
        .clone()
        .try_into()
        .map_err(|_| {
        StdError::generic_err("proof_epoch_submitted is not correctly formatted")
    })?;

    Ok((epoch, raw_ckpt, proof_epoch_sealed, txs_info))
}

/// init initialises the Babylon epoch chain storage
pub fn init(
    storage: &mut dyn Storage,
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof_epoch_sealed: &ProofEpochSealed,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
) -> Result<(), BabylonEpochChainError> {
    // verify epoch and checkpoint, including
    // - whether the epoch is sealed or not
    // - whether the checkpoint is finalised
    let verified_tuple =
        verify_epoch_and_checkpoint(storage, epoch, raw_ckpt, proof_epoch_sealed, txs_info)?;

    // all good, init base
    set_base_epoch(storage, epoch)?;
    // then insert everything and update last finalised epoch
    Ok(insert_epoch_and_checkpoint(storage, &verified_tuple)?)
}

/// handle_epoch handles a BTC-finalised epoch by using the raw checkpoint
/// and inclusion proofs
pub fn handle_epoch_and_checkpoint(
    storage: &mut dyn Storage,
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof_epoch_sealed: &ProofEpochSealed,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
) -> Result<(), BabylonEpochChainError> {
    // verify epoch and checkpoint, including
    // - whether the epoch/checkpoint are sealed or not
    // - whether the checkpoint is finalised
    let verified_tuple =
        verify_epoch_and_checkpoint(storage, epoch, raw_ckpt, proof_epoch_sealed, txs_info)?;

    // all good, insert everything and update last finalised epoch
    Ok(insert_epoch_and_checkpoint(storage, &verified_tuple)?)
}
