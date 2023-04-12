//! btc_light_client is the storage for the BTC header chain, including
//!   - prefixed storage of all headers, where
//!     - prefix: PREFIX_BTC_LIGHT_CLIENT || KEY_HEADERS
//!     - key: header hash
//!     - value: header
//!   - prefixed storage of hash-height mapping, where
//!     - prefix: PREFIX_BTC_LIGHT_CLIENT || KEY_HASH_TO_HEIGHT
//!     - key: header hash
//!     - value: header height
//!   - prefixed storage of the base header, where
//!     - prefix: PREFIX_BTC_LIGHT_CLIENT
//!     - key: KEY_BASE_HEADER
//!     - value: header
//!   - prefixed storage of the chain tip, where
//!     - prefix: PREFIX_BTC_LIGHT_CLIENT
//!     - key: KEY_TIP
//!     - value: header

use crate::error;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use cosmwasm_std::Storage;
use cosmwasm_storage::{prefixed, PrefixedStorage};
use prost::Message;

pub const PREFIX_BTC_LIGHT_CLIENT: &[u8] = &[1];
pub const KEY_HEADERS: &[u8] = &[1];
pub const KEY_HASH_TO_HEIGHT: &[u8] = &[2];
pub const KEY_TIP: &[u8] = &[3];
pub const KEY_BASE_HEADER: &[u8] = &[4];

// getters for storages
fn get_storage_headers(storage: &mut dyn Storage) -> PrefixedStorage {
    PrefixedStorage::multilevel(storage, &[PREFIX_BTC_LIGHT_CLIENT, KEY_HEADERS])
}

fn get_storage_h2h(storage: &mut dyn Storage) -> PrefixedStorage {
    PrefixedStorage::multilevel(storage, &[PREFIX_BTC_LIGHT_CLIENT, KEY_HASH_TO_HEIGHT])
}

fn get_storage_tip(storage: &mut dyn Storage) -> PrefixedStorage {
    prefixed(storage, PREFIX_BTC_LIGHT_CLIENT)
}

fn get_storage_base_header(storage: &mut dyn Storage) -> PrefixedStorage {
    prefixed(storage, PREFIX_BTC_LIGHT_CLIENT)
}

// getter/setter for base header
pub fn get_base_header(storage: &mut dyn Storage) -> BtcHeaderInfo {
    let storage_base_header = get_storage_base_header(storage);
    let base_header_bytes = storage_base_header.get(KEY_BASE_HEADER).unwrap();
    // NOTE: if init is successful, then base header is guaranteed to be correct
    return BtcHeaderInfo::decode(base_header_bytes.as_slice()).unwrap();
}

fn set_base_header(storage: &mut dyn Storage, base_header: &BtcHeaderInfo) {
    let mut storage_base_header = get_storage_base_header(storage);
    let base_header_bytes: &[u8] = &base_header.encode_to_vec();
    storage_base_header.set(KEY_BASE_HEADER, base_header_bytes);
}

// getter/setter for chain tip
pub fn get_tip(storage: &mut dyn Storage) -> Result<BtcHeaderInfo, prost::DecodeError> {
    let storage_tip = get_storage_tip(storage);
    let tip_bytes = storage_tip.get(KEY_TIP).unwrap();
    return BtcHeaderInfo::decode(tip_bytes.as_slice());
}

fn set_tip(storage: &mut dyn Storage, tip: &BtcHeaderInfo) {
    let mut storage_tip = get_storage_tip(storage);
    let tip_bytes = &tip.encode_to_vec();
    storage_tip.set(KEY_TIP, tip_bytes);
}

// insert_btc_headers inserts BTC headers that have passed the
// verification to the header chain storages, including
// - insert all headers
// - insert all hash-to-height indices
fn insert_btc_headers(storage: &mut dyn Storage, new_headers: &[BtcHeaderInfo]) {
    // append all headers
    let mut storage_headers = get_storage_headers(storage);
    for new_header in new_headers.iter() {
        // insert header
        let hash_bytes: &[u8] = new_header.hash.as_ref();
        let header_bytes: &[u8] = &new_header.encode_to_vec();
        storage_headers.set(hash_bytes, header_bytes);
    }

    // append all hash-to-height indices
    let mut storage_h2h = get_storage_h2h(storage);
    for new_header in new_headers.iter() {
        // insert hash-to-height index
        let height_bytes: &[u8] = &new_header.height.to_be_bytes()[..];
        let hash_bytes: &[u8] = new_header.hash.as_ref();
        storage_h2h.set(hash_bytes, height_bytes);
    }
}

// get_header retrieves the BTC header of a given hash
fn get_header(
    storage: &mut dyn Storage,
    hash: &[u8],
) -> Result<BtcHeaderInfo, error::BTCLightclientError> {
    let storage_headers = get_storage_headers(storage);

    // try to find the header with the given hash
    let header_res = storage_headers.get(hash);
    if header_res.is_none() {
        return Err(error::BTCLightclientError::BTCHeaderNotFoundError {});
    }
    let header_bytes = header_res.unwrap();

    // try to decode the header
    let header_res = BtcHeaderInfo::decode(header_bytes.as_slice());
    if header_res.is_err() {
        return Err(error::BTCLightclientError::BTCHeaderDecodeError {});
    }

    return Ok(header_res.unwrap());
}

/// verify_headers verifies whether `new_headers` are valid consecutive headers
/// after the given `first_header`
fn verify_headers(
    btc_network: &babylon_bitcoin::chain_params::Params,
    first_header: &BtcHeaderInfo,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), error::BTCLightclientError> {
    // verify each new header iteratively
    let mut last_header = first_header.clone();
    for new_header in new_headers.iter() {
        // decode last header to rust-bitcoin's type
        let last_btc_header: babylon_bitcoin::BlockHeader =
            babylon_bitcoin::deserialize(&last_header.header).unwrap();
        // decode this header to rust-bitcoin's type
        let btc_header_res: Result<babylon_bitcoin::BlockHeader, babylon_bitcoin::Error> =
            babylon_bitcoin::deserialize(&new_header.header);
        if btc_header_res.is_err() {
            return Err(error::BTCLightclientError::BTCHeaderDecodeError {});
        }
        let btc_header = btc_header_res.unwrap();

        // validate whether btc_header extends last_btc_header
        let res = babylon_bitcoin::pow::verify_next_header_pow(
            btc_network,
            &last_btc_header,
            &btc_header,
        );
        if res.is_err() {
            return Err(error::BTCLightclientError::BTCHeaderError {});
        }

        // this header is good, verify the next one
        last_header = new_header.clone();
    }
    Ok(())
}

/// init initialises the BTC header chain storage
/// It takes BTC headers between
/// - the BTC tip upon the last finalised epoch
/// - the current tip
pub fn init(
    storage: &mut dyn Storage,
    headers: &[BtcHeaderInfo],
) -> Result<(), error::BTCLightclientError> {
    let cfg = super::config::get(storage).load()?;
    let btc_network = babylon_bitcoin::chain_params::get_chain_params(cfg.network);

    // ensure there are >=w+1 headers, i.e., a base header and at least w subsequent
    // ones as a w-deep proof
    if (headers.len() as u64) < cfg.checkpoint_finalization_timeout + 1 {
        return Err(error::BTCLightclientError::InitError {});
    }

    // base header is the first header in the list
    let base_header = headers.first().unwrap();

    // decode this header to rust-bitcoin's type
    let base_btc_header_res: Result<babylon_bitcoin::BlockHeader, babylon_bitcoin::Error> =
        babylon_bitcoin::deserialize(&base_header.header);
    if base_btc_header_res.is_err() {
        return Err(error::BTCLightclientError::BTCHeaderDecodeError {});
    }
    let base_btc_header = base_btc_header_res.unwrap();

    // verify the base header's pow
    if let Err(_) = babylon_bitcoin::pow::verify_header_pow(&btc_network, &base_btc_header) {
        return Err(error::BTCLightclientError::BTCHeaderError {});
    }

    // verify subsequent headers
    verify_headers(&btc_network, base_header, &headers[1..headers.len()])?;

    // byte representation of the base header and its metadata
    let height_bytes: &[u8] = &base_header.height.to_be_bytes()[..];
    let hash_bytes: &[u8] = base_header.hash.as_ref();
    let base_header_bytes: &[u8] = &base_header.encode_to_vec();

    // initialise headers storage
    let mut storage_headers = get_storage_headers(storage);
    storage_headers.set(hash_bytes, base_header_bytes);

    // initialise hash-to-height storage
    let mut storage_h2h = get_storage_h2h(storage);
    storage_h2h.set(hash_bytes, height_bytes);

    // initialise tip storage
    set_tip(storage, base_header);

    // initialise base header
    // NOTE: not changeable in the future
    set_base_header(storage, base_header);

    Ok(())
}

/// handle_btc_headers_from_babylon verifies and inserts a number of
/// finalised BTC headers to the header chain storage, and update
/// the chain tip.
///
/// NOTE: upon each finalised epoch e, Babylon will send BTC headers between
/// - the common ancestor of
///   - BTC tip upon finalising epoch e-1
///   - BTC tip upon finalising epoch e,
/// - BTC tip upon finalising epoch e
/// such that Babylon contract maintains the same canonical BTC header chain
/// as Babylon.
/// TODO: implement fork choice and allow anyone to submit BTC headers to contract
pub fn handle_btc_headers_from_babylon(
    storage: &mut dyn Storage,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), error::BTCLightclientError> {
    let cfg = super::config::get(storage).load()?;
    let btc_network = babylon_bitcoin::chain_params::get_chain_params(cfg.network);

    // ensure the first header's previous header exists in KVStore
    let first_new_header = new_headers.first().unwrap();
    let first_new_btc_header_res: Result<babylon_bitcoin::BlockHeader, babylon_bitcoin::Error> =
        babylon_bitcoin::deserialize(&first_new_header.header);
    if first_new_btc_header_res.is_err() {
        return Err(error::BTCLightclientError::BTCHeaderDecodeError {});
    }
    let first_new_btc_header = first_new_btc_header_res.unwrap();

    // get the previous header in storage
    let last_hash = first_new_btc_header.prev_blockhash;
    let last_header = get_header(storage, last_hash.to_vec().as_ref())?;

    // verify each new header after last_header iteratively
    verify_headers(&btc_network, &last_header, new_headers)?;

    // all good, append all headers to the BTC light client stores
    insert_btc_headers(storage, &new_headers);

    // update tip
    let new_tip = new_headers.last().unwrap();
    set_tip(storage, &new_tip);

    Ok(())
}
