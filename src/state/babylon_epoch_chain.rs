//! babylon_epoch_chain is the storage for the chain of **finalised** Babylon epochs.
//! It maintains a chain of finalised Babylon epochs.
//! The storage includes:
//!   - prefixed storage of all epochs, where
//!     - prefix: PREFIX_BABYLON_EPOCH_CHAIN || KEY_EPOCHS
//!     - key: epoch number
//!     - value: epoch metadata
//!   - prefixed storage of all checkpoints, where
//!     - prefix: PREFIX_BABYLON_EPOCH_CHAIN || KEY_CHECKPOINTS
//!     - key: epoch number
//!     - value: epoch's earliest checkpoint
//!   - prefixed storage of the base epoch
//!     - prefix: PREFIX_BABYLON_EPOCH_CHAIN
//!     - key: KEY_BASE_EPOCH
//!     - value: epoch metadata
//!   - prefixed storage of the last **finalised** epoch
//!     - prefix: PREFIX_BABYLON_EPOCH_CHAIN
//!     - key: KEY_LAST_FINALIZED_EPOCH
//!     - value: epoch metadata
//! NOTE: the Babylon epoch chain is always finalised, i.e., w-deep on BTC.

use crate::error;
use crate::utils::babylon_epoch_chain::{
    verify_checkpoint_submitted, verify_epoch_sealed, NUM_BTC_TXS,
};
use babylon_bitcoin::BlockHeader;
use babylon_proto::babylon::btccheckpoint::v1::TransactionInfo;
use babylon_proto::babylon::checkpointing::v1::RawCheckpoint;
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::ProofEpochSealed;
use cosmwasm_std::Storage;
use cosmwasm_storage::{prefixed, PrefixedStorage};
use hex::ToHex;
use prost::Message;

pub const PREFIX_BABYLON_EPOCH_CHAIN: &[u8] = &[2];
pub const KEY_EPOCHS: &[u8] = &[1];
pub const KEY_CHECKPOINTS: &[u8] = &[2];
pub const KEY_BASE_EPOCH: &[u8] = &[3];
pub const KEY_LAST_FINALIZED_EPOCH: &[u8] = &[4];

// getters for storages
fn get_storage_epochs(storage: &mut dyn Storage) -> PrefixedStorage {
    PrefixedStorage::multilevel(storage, &[PREFIX_BABYLON_EPOCH_CHAIN, KEY_EPOCHS])
}

fn get_storage_checkpoints(storage: &mut dyn Storage) -> PrefixedStorage {
    PrefixedStorage::multilevel(storage, &[PREFIX_BABYLON_EPOCH_CHAIN, KEY_CHECKPOINTS])
}

fn get_storage_base_epoch(storage: &mut dyn Storage) -> PrefixedStorage {
    prefixed(storage, PREFIX_BABYLON_EPOCH_CHAIN)
}

fn get_storage_last_finalized_epoch(storage: &mut dyn Storage) -> PrefixedStorage {
    prefixed(storage, PREFIX_BABYLON_EPOCH_CHAIN)
}

// getter/setter for base epoch
pub fn get_base_epoch(storage: &mut dyn Storage) -> Epoch {
    let storage_base_epoch = get_storage_base_epoch(storage);
    let base_epoch_bytes = storage_base_epoch.get(KEY_BASE_EPOCH).unwrap();
    // NOTE: if init is successful, then base epoch is guaranteed to be correct
    return Epoch::decode(base_epoch_bytes.as_slice()).unwrap();
}

fn set_base_epoch(storage: &mut dyn Storage, base_epoch: &Epoch) {
    let mut storage_base_epoch = get_storage_base_epoch(storage);
    let base_epoch_bytes: &[u8] = &base_epoch.encode_to_vec();
    storage_base_epoch.set(KEY_BASE_EPOCH, base_epoch_bytes);
}

// getter/setter for last finalised epoch
pub fn get_last_finalized_epoch(storage: &mut dyn Storage) -> Result<Epoch, prost::DecodeError> {
    let storage_last_finalized_epoch = get_storage_last_finalized_epoch(storage);
    let last_finalized_epoch_bytes = storage_last_finalized_epoch
        .get(KEY_LAST_FINALIZED_EPOCH)
        .unwrap();
    Epoch::decode(last_finalized_epoch_bytes.as_slice())
}

fn set_last_finalized_epoch(storage: &mut dyn Storage, last_finalized_epoch: &Epoch) {
    let mut storage_last_finalized_epoch = get_storage_last_finalized_epoch(storage);
    let last_finalized_epoch_bytes: &[u8] = &last_finalized_epoch.encode_to_vec();
    storage_last_finalized_epoch.set(KEY_LAST_FINALIZED_EPOCH, last_finalized_epoch_bytes);
}

/// get_epoch retrieves the metadata of a given epoch
pub fn get_epoch(
    storage: &mut dyn Storage,
    epoch_number: u64,
) -> Result<Epoch, error::BabylonEpochChainError> {
    let storage_epochs = get_storage_epochs(storage);

    // try to find the epoch metadata of the given epoch
    let epoch_res = storage_epochs.get(&epoch_number.to_be_bytes());
    if epoch_res.is_none() {
        return Err(error::BabylonEpochChainError::EpochNotFoundError {
            epoch_number: epoch_number,
        });
    }
    let epoch_bytes = epoch_res.unwrap();

    // try to decode the epoch
    let epoch_res = Epoch::decode(epoch_bytes.as_slice())?;

    return Ok(epoch_res);
}

/// get_checkpoint retrieves the checkpoint of a given epoch
pub fn get_checkpoint(
    storage: &mut dyn Storage,
    epoch_number: u64,
) -> Result<RawCheckpoint, error::BabylonEpochChainError> {
    let storage_checkpoints = get_storage_checkpoints(storage);

    // try to find the checkpoint of the given epoch
    let ckpt_res = storage_checkpoints.get(&epoch_number.to_be_bytes());
    if ckpt_res.is_none() {
        return Err(error::BabylonEpochChainError::CheckpointNotFoundError {
            epoch_number: epoch_number,
        });
    }
    let ckpt_bytes = ckpt_res.unwrap();

    // try to decode the checkpoint
    let ckpt_res = RawCheckpoint::decode(ckpt_bytes.as_slice())?;

    return Ok(ckpt_res);
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
    btc_headers: &[BlockHeader; NUM_BTC_TXS],
) -> Result<VerifiedEpochAndCheckpoint, error::BabylonEpochChainError> {
    let cfg = super::config::get(storage).load()?;

    // ensure that raw_ckpt is corresponding to the epoch
    if epoch.epoch_number != raw_ckpt.epoch_num {
        return Err(error::BabylonEpochChainError::CheckpointNotMatchError {
            ckpt_epoch_number: raw_ckpt.epoch_num,
            epoch_number: epoch.epoch_number,
        });
    }

    // this will be used for checking w-deep later
    let mut min_height: u64 = std::u64::MAX;

    // ensure the given btc headers are in BTC light clients
    for btc_header in btc_headers {
        let hash = btc_header.block_hash();
        let header_res = super::btc_light_client::get_header(storage, &hash);
        if header_res.is_err() {
            return Err(error::BabylonEpochChainError::BTCHeaderNotFoundError {
                hash: hash.encode_hex(),
            });
        }
        // refresh min_height
        let header_height = header_res.unwrap().height;
        if min_height > header_height {
            min_height = header_height;
        }
    }

    // ensure at least 1 given btc headers are finalised, i.e., w-deep
    let tip_height = super::btc_light_client::get_tip(storage).height;
    if min_height + cfg.checkpoint_finalization_timeout > tip_height {
        return Err(error::BabylonEpochChainError::BTCHeaderNotDeepEnough {
            w: cfg.checkpoint_finalization_timeout,
        });
    }

    // verify the checkpoint is submitted, i.e., committed to the 2 BTC headers
    let res_submitted =
        verify_checkpoint_submitted(raw_ckpt, txs_info, btc_headers, &cfg.babylon_tag);
    if res_submitted.is_err() {
        return Err(error::BabylonEpochChainError::CheckpointNotSubmitted {});
    }

    // verify the epoch is sealed by its validator set
    let res_sealed = verify_epoch_sealed(epoch, raw_ckpt, proof_epoch_sealed);
    if res_sealed.is_err() {
        return Err(error::BabylonEpochChainError::EpochNotSealed {});
    }

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
) {
    // insert epoch metadata
    let mut storage_epochs = get_storage_epochs(storage);
    let epoch_number_bytes = verified_tuple.epoch.epoch_number.to_be_bytes();
    let epoch_bytes = verified_tuple.epoch.encode_to_vec();
    storage_epochs.set(&epoch_number_bytes, &epoch_bytes);

    // insert raw ckpt
    let mut storage_ckpts = get_storage_checkpoints(storage);
    let raw_ckpt_bytes = verified_tuple.raw_ckpt.encode_to_vec();
    storage_ckpts.set(&epoch_number_bytes, &raw_ckpt_bytes);

    // update last finalised epoch
    set_last_finalized_epoch(storage, &verified_tuple.epoch);
}

/// init initialises the Babylon epoch chain storage
pub fn init(
    storage: &mut dyn Storage,
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof_epoch_sealed: &ProofEpochSealed,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
    btc_headers: &[BlockHeader; NUM_BTC_TXS],
) -> Result<(), error::BabylonEpochChainError> {
    // verify epoch and checkpoint, including
    // - whether the epoch is sealed or not
    // - whether the checkpoint is finalised
    let verified_tuple = verify_epoch_and_checkpoint(
        storage,
        epoch,
        raw_ckpt,
        proof_epoch_sealed,
        txs_info,
        btc_headers,
    )?;

    // all good, init base
    set_base_epoch(storage, epoch);
    // then insert everything and update last finalised epoch
    insert_epoch_and_checkpoint(storage, &verified_tuple);

    Ok(())
}

/// handle_epoch handles a BTC-finalised epoch by using the raw checkpoint
/// and inclusion proofs
pub fn handle_epoch_and_checkpoint(
    storage: &mut dyn Storage,
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof_epoch_sealed: &ProofEpochSealed,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
    btc_headers: &[BlockHeader; NUM_BTC_TXS],
) -> Result<(), error::BabylonEpochChainError> {
    // verify epoch and checkpoint, including
    // - whether the epoch/checkpoint are sealed or not
    // - whether the checkpoint is finalised
    let verified_tuple = verify_epoch_and_checkpoint(
        storage,
        epoch,
        raw_ckpt,
        proof_epoch_sealed,
        txs_info,
        btc_headers,
    )?;

    // all good, insert everything and update last finalised epoch
    insert_epoch_and_checkpoint(storage, &verified_tuple);

    Ok(())
}
