//! cz_header_chain is the storage for the chain of **finalised** CZ headers.
//! It maintains a chain of finalised CZ headers.
//! The storage includes:
//!   - prefixed storage of all CZ headers, where
//!     - prefix: PREFIX_CZ_HEADER_CHAIN || KEY_CZ_HEADERS
//!     - key: height
//!     - value: IndexedHeader
//!   - prefixed storage of the last **finalised** CZ header
//!     - prefix: PREFIX_CZ_HEADER_CHAIN
//!     - key: KEY_LAST_CZ_HEADER
//!     - value: IndexedHeader
//! NOTE: the CZ header chain is always finalised, i.e., w-deep on BTC.

use crate::state::PREFIX_CZ_HEADER_CHAIN;
use crate::{error, utils};
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::IndexedHeader;
use cosmwasm_std::Storage;
use cosmwasm_storage::{prefixed, PrefixedStorage};
use prost::Message;
use tendermint_proto::crypto::Proof;
use tendermint_proto::types::TxProof;

pub const KEY_CZ_HEADERS: &[u8] = &[1];
pub const KEY_LAST_CZ_HEADER: &[u8] = &[2];

// getters for storages
fn get_storage_cz_headers(storage: &mut dyn Storage) -> PrefixedStorage {
    PrefixedStorage::multilevel(storage, &[PREFIX_CZ_HEADER_CHAIN, KEY_CZ_HEADERS])
}

fn get_storage_last_cz_header(storage: &mut dyn Storage) -> PrefixedStorage {
    prefixed(storage, PREFIX_CZ_HEADER_CHAIN)
}

// getter/setter for last finalised CZ header
pub fn get_last_cz_header(
    storage: &mut dyn Storage,
) -> Result<IndexedHeader, error::CZHeaderChainError> {
    let storage_last_cz_header = get_storage_last_cz_header(storage);
    let last_cz_header_bytes = storage_last_cz_header
        .get(KEY_LAST_CZ_HEADER)
        .ok_or(error::CZHeaderChainError::NoCZHeader {})?;
    IndexedHeader::decode(last_cz_header_bytes.as_slice())
        .map_err(error::CZHeaderChainError::DecodeError)
}

fn set_last_cz_header(storage: &mut dyn Storage, last_cz_header: &IndexedHeader) {
    let mut storage_last_cz_header = get_storage_last_cz_header(storage);
    let last_cz_header_bytes: &[u8] = &last_cz_header.encode_to_vec();
    storage_last_cz_header.set(KEY_LAST_CZ_HEADER, last_cz_header_bytes);
}

/// get_cz_header gets a CZ header of a given height
pub fn get_cz_header(
    storage: &mut dyn Storage,
    height: u64,
) -> Result<IndexedHeader, error::CZHeaderChainError> {
    let storage_cz_headers = get_storage_cz_headers(storage);

    // try to find the indexed header at the given height
    let cz_header_bytes = storage_cz_headers
        .get(&height.to_be_bytes())
        .ok_or(error::CZHeaderChainError::CZHeaderNotFoundError { height })?;

    // try to decode the indexed_header
    let indexed_header = IndexedHeader::decode(cz_header_bytes.as_slice())?;

    Ok(indexed_header)
}

/// verify_cz_header verifies whether a CZ header is committed to a Babylon epoch, including
/// - The Babylon tx carrying this header is included in a Babylon block
/// - The Babylon block's AppHash is committed to the AppHashRoot of the epoch
fn verify_cz_header(
    storage: &mut dyn Storage,
    cz_header: &IndexedHeader,
    epoch: &Epoch,
    proof_tx_in_block: &TxProof,
    proof_header_in_epoch: &Proof,
) -> Result<(), error::CZHeaderChainError> {
    let _cfg = super::config::get(storage).load()?;

    let babylon_header = cz_header
        .babylon_header
        .as_ref()
        .ok_or(error::CZHeaderChainError::CZHeaderDecodeError {})?;

    // check if the corresponding tx is in the Babylon header
    utils::cz_header_chain::verify_tx_in_block(
        &cz_header.babylon_tx_hash,
        &babylon_header.data_hash,
        proof_tx_in_block,
    )?;

    // check if the Babylon header is in the given epoch
    let babylon_header_app_hash = babylon_header.app_hash.clone();
    utils::cz_header_chain::verify_block_in_epoch(
        &babylon_header_app_hash,
        &epoch.app_hash_root,
        proof_header_in_epoch,
    )?;

    // TODO: check if IndexedHeader is conflicted or not. Still not sure if this check should happen
    // in a relayer/monitor or the smart contract, given that smart contract has no access to the
    // Tendermint ledger

    Ok(())
}

fn insert_cz_header(storage: &mut dyn Storage, cz_header: &IndexedHeader) {
    // insert indexed header
    let mut storage_cz_headers = get_storage_cz_headers(storage);
    let height_bytes = cz_header.height.to_be_bytes();
    let cz_header_bytes = cz_header.encode_to_vec();
    storage_cz_headers.set(&height_bytes, &cz_header_bytes);

    // update last finalised header
    set_last_cz_header(storage, cz_header);
}

pub fn handle_cz_header(
    storage: &mut dyn Storage,
    cz_header: &IndexedHeader,
    epoch: &Epoch,
    proof_tx_in_block: &TxProof,
    proof_header_in_epoch: &Proof,
) -> Result<(), error::CZHeaderChainError> {
    verify_cz_header(
        storage,
        cz_header,
        epoch,
        proof_tx_in_block,
        proof_header_in_epoch,
    )?;
    insert_cz_header(storage, cz_header);

    Ok(())
}
