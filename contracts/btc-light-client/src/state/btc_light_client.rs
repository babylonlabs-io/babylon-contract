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
pub fn init(storage: &mut dyn Storage, headers: &[BtcHeaderInfo]) -> StdResult<()> {
    // Save headers
    insert_headers(storage, headers)?;

    // Save base header and tip
    set_base_header(storage, &headers[0])?;
    set_tip(storage, headers.last().unwrap())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{get_btc_lc_fork_headers, get_btc_lc_headers, mock_storage, setup};

    #[test]
    fn btc_lc_works() {
        let mut storage = mock_storage();
        let w = setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // testing initialisation with w+1 headers
        let test_init_headers: &[BtcHeaderInfo] = &test_headers[0..(w + 1) as usize];
        init(&mut storage, test_init_headers).unwrap();

        ensure_base_and_tip(&storage, test_init_headers);

        // ensure all headers are correctly inserted
        ensure_headers(&storage, test_init_headers);

        // handling subsequent headers
        let test_new_headers = &test_headers[(w + 1) as usize..test_headers.len()];
        insert_headers(&mut storage, test_new_headers).unwrap();

        // ensure tip is set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all new headers are correctly inserted
        ensure_headers(&storage, test_new_headers);
    }

    #[track_caller]
    fn ensure_headers(storage: &dyn Storage, headers: &[BtcHeaderInfo]) {
        for header_expected in headers {
            let header_actual = get_header(storage, header_expected.height).unwrap();
            assert_eq!(*header_expected, header_actual);
            let header_by_hash =
                get_header_by_hash(storage, header_expected.hash.as_ref()).unwrap();
            assert_eq!(*header_expected, header_by_hash);
        }
    }

    #[track_caller]
    fn ensure_base_and_tip(storage: &dyn Storage, test_init_headers: &[BtcHeaderInfo]) {
        // ensure the base header is set
        let base_expected = test_init_headers.first().unwrap();
        let base_actual = get_base_header(storage).unwrap();
        assert_eq!(*base_expected, base_actual);
        // ensure the tip header is set
        let tip_expected = test_init_headers.last().unwrap();
        let tip_actual = get_tip(storage).unwrap();
        assert_eq!(*tip_expected, tip_actual);
    }

    // Must match `forkHeaderHeight` in datagen/main.go
    const FORK_HEADER_HEIGHT: u32 = 90;

    #[test]
    fn btc_lc_fork_accepted() {
        let mut storage = mock_storage();
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // initialize with all headers
        init(&mut storage, &test_headers).unwrap();

        // ensure base and tip are set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);

        // get fork headers
        let test_fork_headers = get_btc_lc_fork_headers();

        // handling fork headers
        insert_headers(&mut storage, &test_fork_headers).unwrap();

        // ensure the base header is unchanged
        let base_expected = test_headers.first().unwrap();
        let base_actual = get_base_header(&storage).unwrap();
        assert_eq!(*base_expected, base_actual);
        // ensure the tip header is set to the last fork header
        let tip_expected = test_fork_headers.last().unwrap();
        let tip_actual = get_tip(&storage).unwrap();
        assert_eq!(*tip_expected, tip_actual);

        // ensure all initial headers are still inserted
        ensure_headers(&storage, &test_headers[..FORK_HEADER_HEIGHT as usize]);

        // ensure all forked headers are correctly inserted
        ensure_headers(&storage, &test_fork_headers);
    }

    #[test]
    fn btc_lc_fork_invalid() {
        let mut storage = mock_storage();
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // initialize with all headers
        init(&mut storage, &test_headers).unwrap();

        // ensure base and tip are set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);

        // get fork headers
        let test_fork_headers = get_btc_lc_fork_headers();

        // Make the fork headers invalid
        let mut invalid_fork_headers = test_fork_headers.clone();
        invalid_fork_headers.push(test_fork_headers.last().unwrap().clone());

        // handling invalid fork headers
        let res = insert_headers(&mut storage, &invalid_fork_headers);
        assert!(res.is_err());

        // ensure base and tip are unchanged
        ensure_base_and_tip(&storage, &test_headers);
        // ensure that all headers are correctly inserted
        ensure_headers(&storage, &test_headers);
    }

    #[test]
    fn btc_lc_fork_invalid_height() {
        let mut storage = mock_storage();
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // initialize with all headers
        init(&mut storage, &test_headers).unwrap();

        // ensure base and tip are set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);

        // get fork headers
        let test_fork_headers = get_btc_lc_fork_headers();

        // Make the fork headers invalid due to one of the headers having the wrong height
        let mut invalid_fork_headers = test_fork_headers.clone();
        let mut wrong_header = invalid_fork_headers.last().unwrap().clone();
        wrong_header.height += 1;
        let len = invalid_fork_headers.len();
        invalid_fork_headers[len - 1] = wrong_header;

        // handling invalid fork headers
        let res = insert_headers(&mut storage, &invalid_fork_headers);
        assert!(res.is_err());

        // ensure base and tip are unchanged
        ensure_base_and_tip(&storage, &test_headers);
        // ensure that all headers are correctly inserted
        ensure_headers(&storage, &test_headers);
    }
}
