use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::{Bound, Item, Map};
use hex::ToHex;
use prost::Message;

use crate::error::ContractError;

pub const BTC_TIP_KEY: &str = "btc_lc_tip";

pub const BTC_HEADERS: Map<u32, Vec<u8>> = Map::new("btc_lc_headers");
pub const BTC_HEADER_BASE: Item<Vec<u8>> = Item::new("btc_lc_header_base");
pub const BTC_HEIGHTS: Map<&[u8], u32> = Map::new("btc_lc_heights");
pub const BTC_TIP: Item<Vec<u8>> = Item::new(BTC_TIP_KEY);

// getters for storages

// is_initialized checks if the BTC light client has been initialised or not
// the check is done by checking the existence of the base header
pub fn is_initialized(storage: &mut dyn Storage) -> bool {
    BTC_HEADER_BASE.load(storage).is_ok()
}

// getter/setter for base header
pub fn get_base_header(storage: &dyn Storage) -> Result<BtcHeaderInfo, ContractError> {
    // NOTE: if init is successful, then base header is guaranteed to be in storage and decodable
    let base_header_bytes = BTC_HEADER_BASE.load(storage)?;
    BtcHeaderInfo::decode(base_header_bytes.as_slice()).map_err(ContractError::DecodeError)
}

pub fn set_base_header(storage: &mut dyn Storage, base_header: &BtcHeaderInfo) -> StdResult<()> {
    let base_header_bytes = base_header.encode_to_vec();
    BTC_HEADER_BASE.save(storage, &base_header_bytes)
}

// getter/setter for chain tip
pub fn get_tip(storage: &dyn Storage) -> Result<BtcHeaderInfo, ContractError> {
    let tip_bytes = BTC_TIP.load(storage)?;
    // NOTE: if init is successful, then tip header is guaranteed to be correct
    BtcHeaderInfo::decode(tip_bytes.as_slice()).map_err(ContractError::DecodeError)
}

pub fn set_tip(storage: &mut dyn Storage, tip: &BtcHeaderInfo) -> StdResult<()> {
    let tip_bytes = &tip.encode_to_vec();
    BTC_TIP.save(storage, tip_bytes)
}

// insert_headers inserts BTC headers that have passed the verification to the header chain
// storages, including
// - insert all headers
// - insert all hash-to-height indices
pub fn insert_headers(storage: &mut dyn Storage, new_headers: &[BtcHeaderInfo]) -> StdResult<()> {
    // Add all the headers by height
    for new_header in new_headers.iter() {
        // insert header
        let hash_bytes: &[u8] = new_header.hash.as_ref();
        let header_bytes = new_header.encode_to_vec();
        BTC_HEADERS.save(storage, new_header.height, &header_bytes)?;
        BTC_HEIGHTS.save(storage, hash_bytes, &new_header.height)?;
    }
    Ok(())
}

// remove_headers removes BTC headers from the header chain storages, including
// - remove all hash-to-height indices
pub fn remove_headers(
    storage: &mut dyn Storage,
    tip_header: &BtcHeaderInfo,
    parent_header: &BtcHeaderInfo,
) -> Result<(), ContractError> {
    // Remove all the headers by hash starting from the tip, until hitting the parent header
    let mut rem_header = tip_header.clone();
    while rem_header.hash != parent_header.hash {
        // Remove header from storage
        BTC_HEIGHTS.remove(storage, rem_header.hash.as_ref());
        // Obtain the previous header
        rem_header = get_header(storage, rem_header.height - 1)?;
    }
    Ok(())
}

// get_header retrieves the BTC header of a given height
pub fn get_header(storage: &dyn Storage, height: u32) -> Result<BtcHeaderInfo, ContractError> {
    // Try to find the header with the given hash
    let header_bytes = BTC_HEADERS
        .load(storage, height)
        .map_err(|_| ContractError::BTCHeaderNotFoundError { height })?;

    BtcHeaderInfo::decode(header_bytes.as_slice()).map_err(ContractError::DecodeError)
}

// get_header_by_hash retrieves the BTC header of a given hash
pub fn get_header_by_hash(
    storage: &dyn Storage,
    hash: &[u8],
) -> Result<BtcHeaderInfo, ContractError> {
    // Try to find the height with the given hash
    let height =
        BTC_HEIGHTS
            .load(storage, hash)
            .map_err(|_| ContractError::BTCHeightNotFoundError {
                hash: hash.encode_hex::<String>(),
            })?;

    get_header(storage, height)
}

// get_headers retrieves BTC headers in a given range
pub fn get_headers(
    storage: &dyn Storage,
    start_after: Option<u32>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<Vec<BtcHeaderInfo>, ContractError> {
    let limit = limit.unwrap_or(10) as usize;
    let reverse = reverse.unwrap_or(false);

    let (start, end, order) = match (start_after, reverse) {
        (Some(start), true) => (None, Some(Bound::exclusive(start)), Descending),
        (Some(start), false) => (Some(Bound::exclusive(start)), None, Ascending),
        (None, true) => (None, None, Descending),
        (None, false) => (None, None, Ascending),
    };

    let headers = BTC_HEADERS
        .range(storage, start, end, order)
        .take(limit)
        .map(|item| {
            let (_, header_bytes) = item?;
            BtcHeaderInfo::decode(header_bytes.as_slice()).map_err(ContractError::DecodeError)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(headers)
}
