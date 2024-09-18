//! btc_light_client is the storage for the BTC header chain
use babylon_bitcoin::{BlockHash, BlockHeader};
use prost::Message;
use std::str::FromStr;

use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::{Bound, Item, Map};
use hex::ToHex;

use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;

use crate::error::BTCLightclientError;
use crate::msg::btc_header::BtcHeader;
use crate::state::config::CONFIG;
use crate::utils::btc_light_client::{total_work, verify_headers, zero_work};

pub const BTC_TIP_KEY: &str = "btc_lc_tip";

pub const BTC_HEADERS: Map<u64, Vec<u8>> = Map::new("btc_lc_headers");
pub const BTC_HEADER_BASE: Item<Vec<u8>> = Item::new("btc_lc_header_base");
pub const BTC_HEIGHTS: Map<&[u8], u64> = Map::new("btc_lc_heights");
pub const BTC_TIP: Item<Vec<u8>> = Item::new(BTC_TIP_KEY);

// getters for storages

// is_initialized checks if the BTC light client has been initialised or not
// the check is done by checking the existence of the base header
pub fn is_initialized(storage: &mut dyn Storage) -> bool {
    BTC_HEADER_BASE.load(storage).is_ok()
}

// getter/setter for base header
pub fn get_base_header(storage: &dyn Storage) -> Result<BtcHeaderInfo, BTCLightclientError> {
    // NOTE: if init is successful, then base header is guaranteed to be in storage and decodable
    let base_header_bytes = BTC_HEADER_BASE.load(storage)?;
    BtcHeaderInfo::decode(base_header_bytes.as_slice()).map_err(BTCLightclientError::DecodeError)
}

fn set_base_header(storage: &mut dyn Storage, base_header: &BtcHeaderInfo) -> StdResult<()> {
    let base_header_bytes = base_header.encode_to_vec();
    BTC_HEADER_BASE.save(storage, &base_header_bytes)
}

// getter/setter for chain tip
pub fn get_tip(storage: &dyn Storage) -> Result<BtcHeaderInfo, BTCLightclientError> {
    let tip_bytes = BTC_TIP.load(storage)?;
    // NOTE: if init is successful, then tip header is guaranteed to be correct
    BtcHeaderInfo::decode(tip_bytes.as_slice()).map_err(BTCLightclientError::DecodeError)
}

fn set_tip(storage: &mut dyn Storage, tip: &BtcHeaderInfo) -> StdResult<()> {
    let tip_bytes = &tip.encode_to_vec();
    BTC_TIP.save(storage, tip_bytes)
}

// insert_headers inserts BTC headers that have passed the verification to the header chain
// storages, including
// - insert all headers
// - insert all hash-to-height indices
fn insert_headers(storage: &mut dyn Storage, new_headers: &[BtcHeaderInfo]) -> StdResult<()> {
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
fn remove_headers(
    storage: &mut dyn Storage,
    tip_header: &BtcHeaderInfo,
    parent_header: &BtcHeaderInfo,
) -> Result<(), BTCLightclientError> {
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
pub fn get_header(
    storage: &dyn Storage,
    height: u64,
) -> Result<BtcHeaderInfo, BTCLightclientError> {
    // Try to find the header with the given hash
    let header_bytes = BTC_HEADERS
        .load(storage, height)
        .map_err(|_| BTCLightclientError::BTCHeaderNotFoundError { height })?;

    // Try to decode the header
    let header = BtcHeaderInfo::decode(header_bytes.as_slice())
        .map_err(|_| BTCLightclientError::BTCHeaderDecodeError {})?;

    Ok(header)
}

// get_header_by_hash retrieves the BTC header of a given hash
pub fn get_header_by_hash(
    storage: &dyn Storage,
    hash: &[u8],
) -> Result<BtcHeaderInfo, BTCLightclientError> {
    let height = get_header_height(storage, hash)?;
    get_header(storage, height)
}

// get_header height retrieves the BTC header height of a given BTC hash
pub fn get_header_height(storage: &dyn Storage, hash: &[u8]) -> Result<u64, BTCLightclientError> {
    let height = BTC_HEIGHTS.load(storage, hash).map_err(|_| {
        BTCLightclientError::BTCHeightNotFoundError {
            hash: hash.encode_hex(),
        }
    })?;
    Ok(height)
}

// Settings for pagination
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

// get_headers retrieves the BTC headers after a given height, up to limit headers
pub fn get_headers(
    storage: &dyn Storage,
    start_after: Option<u64>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<Vec<BtcHeaderInfo>, BTCLightclientError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after.map(Bound::exclusive);
    let (start, end, order) = if reverse.unwrap_or(false) {
        (None, start_after, Descending)
    } else {
        (start_after, None, Ascending)
    };

    BTC_HEADERS
        .range_raw(storage, start, end, order)
        .take(limit)
        .map(|item| {
            let (_, v) = item?;
            Ok(BtcHeaderInfo::decode(&*v)?)
        })
        .collect()
}

/// init initialises the BTC header chain storage
/// It takes BTC headers between
/// - the BTC tip upon the last finalised epoch
/// - the current tip
pub fn init(
    storage: &mut dyn Storage,
    headers: &[BtcHeaderInfo],
) -> Result<(), BTCLightclientError> {
    let cfg = CONFIG.load(storage)?;
    let btc_network = babylon_bitcoin::chain_params::get_chain_params(cfg.network);

    // ensure there are >=w+1 headers, i.e. a base header and at least w subsequent
    // ones as a w-deep proof
    if (headers.len() as u64) < cfg.checkpoint_finalization_timeout + 1 {
        return Err(BTCLightclientError::InitErrorLength(
            cfg.checkpoint_finalization_timeout + 1,
        ));
    }

    // base header is the first header in the list
    let base_header = headers.first().ok_or(BTCLightclientError::InitError {})?;

    // decode this header to rust-bitcoin's type
    let base_btc_header: BlockHeader = babylon_bitcoin::deserialize(base_header.header.as_ref())
        .map_err(|_| BTCLightclientError::BTCHeaderDecodeError {})?;

    // verify the base header's pow
    if babylon_bitcoin::pow::verify_header_pow(&btc_network, &base_btc_header).is_err() {
        return Err(BTCLightclientError::BTCHeaderError {});
    }

    // verify subsequent headers
    let new_headers = &headers[1..headers.len()];
    verify_headers(&btc_network, base_header, new_headers)?;

    // all good, set base header, insert all headers, and set tip

    // initialise base header
    // NOTE: not changeable in the future
    set_base_header(storage, base_header)?;
    // insert all headers
    insert_headers(storage, headers)?;
    // set tip header
    set_tip(
        storage,
        headers.last().ok_or(BTCLightclientError::InitError {})?,
    )?;
    Ok(())
}

/// `init_from_user` initialises the BTC header chain storage.
/// Alternative to `init`, in which a user sends the initial batch of headers, instead of Babylon.
///
/// Starts from zero work and heights. Mostly useful for integration tests.
pub fn init_from_user(
    storage: &mut dyn Storage,
    headers: &[BtcHeader],
) -> Result<(), BTCLightclientError> {
    let mut prev_height = 0;
    let mut prev_work = zero_work();
    let headers = headers
        .iter()
        .map(|header| {
            let btc_header = header.to_btc_header_info(prev_height, prev_work)?;
            prev_height = btc_header.height;
            prev_work = total_work(&btc_header)?;
            Ok(btc_header)
        })
        .collect::<Result<Vec<BtcHeaderInfo>, BTCLightclientError>>()?;
    init(storage, &headers)
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
pub fn handle_btc_headers_from_babylon(
    storage: &mut dyn Storage,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), BTCLightclientError> {
    let cfg = CONFIG.load(storage)?;
    let btc_network = babylon_bitcoin::chain_params::get_chain_params(cfg.network);

    let cur_tip = get_tip(storage)?;
    let cur_tip_hash = cur_tip.hash.clone();

    // decode the first header in these new headers
    let first_new_header = new_headers
        .first()
        .ok_or(BTCLightclientError::BTCHeaderEmpty {})?;
    let first_new_btc_header: BlockHeader =
        babylon_bitcoin::deserialize(first_new_header.header.as_ref())
            .map_err(|_| BTCLightclientError::BTCHeaderDecodeError {})?;

    if first_new_btc_header.prev_blockhash.as_ref() == cur_tip_hash.to_vec() {
        // Most common case: extending the current tip

        // Verify each new header after `current_tip` iteratively
        verify_headers(&btc_network, &cur_tip.clone(), new_headers)?;

        // All good, add all the headers to the BTC light client store
        insert_headers(storage, new_headers)?;

        // Update tip
        let new_tip = new_headers
            .last()
            .ok_or(BTCLightclientError::BTCHeaderEmpty {})?;
        set_tip(storage, new_tip)?;
    } else {
        // Here we received a potential new fork
        let parent_hash = first_new_btc_header.prev_blockhash.as_ref();
        let fork_parent = get_header_by_hash(storage, parent_hash)?;

        // Verify each new header after `fork_parent` iteratively
        verify_headers(&btc_network, &fork_parent, new_headers)?;

        let new_tip = new_headers
            .last()
            .ok_or(BTCLightclientError::BTCHeaderEmpty {})?;

        let new_tip_work = total_work(new_tip)?;
        let cur_tip_work = total_work(&cur_tip)?;
        if new_tip_work <= cur_tip_work {
            return Err(BTCLightclientError::BTCChainWithNotEnoughWork(
                new_tip_work,
                cur_tip_work,
            ));
        }

        // Remove all headers from the old fork first
        remove_headers(storage, &cur_tip, &fork_parent)?;

        // All good, add all the headers to the BTC light client store
        insert_headers(storage, new_headers)?;

        // Update tip
        set_tip(storage, new_tip)?;
    }
    Ok(())
}

/// handle_btc_headers_from_user verifies and inserts a number of finalised BTC headers to the
/// header chain storage, and updates the chain's tip.
///
/// This can be used as an alternative to `handle_btc_headers_from_babylon`, for cases in which
/// Babylon itself is unavailable / unresponsive.
/// The user wants to submit BTC headers directly, such that the Babylon contract maintains the same
/// canonical BTC header chain as Babylon.
pub fn handle_btc_headers_from_user(
    storage: &mut dyn Storage,
    new_btc_headers: &[BtcHeader],
) -> Result<(), BTCLightclientError> {
    let first_new_btc_header = new_btc_headers
        .first()
        .ok_or(BTCLightclientError::BTCHeaderEmpty {})?;

    // Decode the btc_header (byte-reversed) prev_blockhash
    let prev_blockhash = BlockHash::from_str(&first_new_btc_header.prev_blockhash)?;

    // Obtain previous header from storage
    let previous_header = get_header_by_hash(storage, prev_blockhash.as_ref())?;

    // Convert new_headers to `BtcHeaderInfo`s
    let mut cur_height = previous_header.height;
    let mut cur_work = total_work(&previous_header)?;
    let mut new_headers_info = vec![];
    for new_btc_header in new_btc_headers.iter() {
        let new_header_info = new_btc_header.to_btc_header_info(cur_height, cur_work)?;
        cur_height += 1;
        cur_work = total_work(&new_header_info)?;
        new_headers_info.push(new_header_info);
    }

    // Call `handle_btc_headers_from_babylon`
    handle_btc_headers_from_babylon(storage, &new_headers_info)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::msg::contract::ExecuteMsg;
    use crate::state::config::Config;
    use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
    use cosmwasm_std::from_json;
    use cosmwasm_std::testing::mock_dependencies;
    use test_utils::{get_btc_lc_fork_headers, get_btc_lc_fork_msg, get_btc_lc_headers};

    pub(crate) fn setup(storage: &mut dyn Storage) -> usize {
        // set config first
        let w: usize = 2;
        let cfg = Config {
            network: babylon_bitcoin::chain_params::Network::Regtest,
            babylon_tag: vec![0x1, 0x2, 0x3, 0x4],
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: w as u64,
            notify_cosmos_zone: false,
            btc_staking: None,
            btc_finality: None,
            consumer_name: None,
            consumer_description: None,
        };
        CONFIG.save(storage, &cfg).unwrap();
        w
    }

    fn get_fork_msg_test_headers() -> Vec<BtcHeader> {
        let testdata = get_btc_lc_fork_msg();
        let resp: ExecuteMsg = from_json(testdata).unwrap();
        match resp {
            ExecuteMsg::BtcHeaders { headers } => headers,
            ExecuteMsg::Slashing { .. } => unreachable!("unexpected slashing message"),
        }
    }

    #[track_caller]
    fn ensure_headers(storage: &dyn Storage, headers: &[BtcHeaderInfo]) {
        for header_expected in headers {
            let actual_height = get_header_height(storage, header_expected.hash.as_ref()).unwrap();
            assert_eq!(header_expected.height, actual_height);
            let header_actual = get_header(storage, header_expected.height).unwrap();
            assert_eq!(*header_expected, header_actual);
        }
    }

    #[track_caller]
    fn ensure_btc_headers(storage: &dyn Storage, headers: &[BtcHeader]) {
        // Existence / inclusion check only, as we don't have the height and cumulative work info
        for header_expected in headers {
            let block_header_expected: BlockHeader = header_expected.try_into().unwrap();
            get_header_by_hash(storage, block_header_expected.block_hash().as_ref()).unwrap();
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

    // btc_lc_works simulates initialisation of BTC light client storage, then insertion of
    // a number of headers. It ensures that the correctness of initialisation/insertion upon
    // a list of correct BTC headers on Bitcoin regtest net.
    #[test]
    fn btc_lc_works() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
        let w = setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // testing initialisation with w+1 headers
        let test_init_headers: &[BtcHeaderInfo] = &test_headers[0..w + 1];
        init(&mut storage, test_init_headers).unwrap();

        ensure_base_and_tip(&storage, test_init_headers);

        // ensure all headers are correctly inserted
        ensure_headers(&storage, test_init_headers);

        // handling subsequent headers
        let test_new_headers = &test_headers[w + 1..test_headers.len()];
        handle_btc_headers_from_babylon(&mut storage, test_new_headers).unwrap();

        // ensure tip is set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all new headers are correctly inserted
        ensure_headers(&storage, test_new_headers);
    }

    // Must match `forkHeaderHeight` in datagen/main.go
    const FORK_HEADER_HEIGHT: u64 = 90;

    // btc_lc_fork_accepted simulates initialization of BTC light client storage,
    // then insertion of a number of headers.
    // It checks the correctness of the fork choice rule for an accepted fork.
    #[test]
    fn btc_lc_fork_accepted() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
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
        handle_btc_headers_from_babylon(&mut storage, &test_fork_headers).unwrap();

        // ensure the base header is set
        let base_expected = test_headers.first().unwrap();
        let base_actual = get_base_header(&storage).unwrap();
        assert_eq!(*base_expected, base_actual);
        // ensure the tip is set
        let tip_expected = test_fork_headers.last().unwrap();
        let tip_actual = get_tip(&storage).unwrap();
        assert_eq!(*tip_expected, tip_actual);

        // ensure all initial headers are still inserted
        ensure_headers(&storage, &test_headers[..FORK_HEADER_HEIGHT as usize]);

        // ensure all forked headers are correctly inserted
        ensure_headers(&storage, &test_fork_headers);

        // check that the original forked headers have been removed from the hash-to-height map
        for header_expected in test_headers[FORK_HEADER_HEIGHT as usize..].iter() {
            assert!(get_header_height(&storage, header_expected.hash.as_ref()).is_err());
        }
    }

    // btc_lc_fork_rejected simulates initialization of BTC light client storage,
    // then insertion of a number of headers.
    // It checks the correctness of the fork choice rule for a rejected fork.
    #[test]
    fn btc_lc_fork_rejected() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // initialize with all headers
        init(&mut storage, &test_headers).unwrap();

        // ensure the base and tip are set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);

        // get fork headers
        let test_fork_headers = get_btc_lc_fork_headers();

        // handling fork headers minus the last
        let res = handle_btc_headers_from_babylon(
            &mut storage,
            &test_fork_headers[..test_fork_headers.len() - 1],
        );
        assert!(matches!(
            res.unwrap_err(),
            BTCLightclientError::BTCChainWithNotEnoughWork(_, _)
        ));

        // ensure base and tip are unchanged
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);
    }

    // btc_lc_fork_invalid simulates initialization of BTC light client storage,
    // then insertion of a number of headers.
    // It checks the correctness of the fork choice rule for an invalid fork (non-consecutive headers).
    #[test]
    fn btc_lc_fork_invalid() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
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
        let res = handle_btc_headers_from_babylon(&mut storage, &invalid_fork_headers);
        assert!(matches!(
            res.unwrap_err(),
            BTCLightclientError::BTCHeaderError {}
        ));

        // ensure base and tip are unchanged
        ensure_base_and_tip(&storage, &test_headers);
        // ensure that all headers are correctly inserted
        ensure_headers(&storage, &test_headers);
    }

    // btc_lc_fork_invalid_height simulates initialization of BTC light client storage,
    // then insertion of a number of headers.
    // It checks the correctness of the fork choice rule for an invalid fork due to a wrong header
    // height.
    #[test]
    fn btc_lc_fork_invalid_height() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
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
        let height = wrong_header.height;
        wrong_header.height += 1;
        let len = invalid_fork_headers.len();
        invalid_fork_headers[len - 1] = wrong_header;

        // handling invalid fork headers
        let res = handle_btc_headers_from_babylon(&mut storage, &invalid_fork_headers);
        assert_eq!(
            res.unwrap_err(),
            BTCLightclientError::BTCWrongHeight(len - 1, height, height + 1)
        );

        // ensure base and tip are unchanged
        ensure_base_and_tip(&storage, &test_headers);
        // ensure that all headers are correctly inserted
        ensure_headers(&storage, &test_headers);
    }

    // btc_lc_fork_invalid_work simulates initialization of BTC light client storage,
    // then insertion of a number of headers.
    // It checks the correctness of the fork choice rule for an invalid fork due to a wrong header
    // work.
    #[test]
    fn btc_lc_fork_invalid_work() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
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

        // Make the fork headers invalid due to one of the headers having the wrong work
        let wrong_header_index = test_fork_headers.len() / 2;
        let mut invalid_fork_headers = test_fork_headers.clone();
        let header = invalid_fork_headers[wrong_header_index].clone();
        let work = header.work.clone();

        let mut wrong_bytes = work.to_vec();
        let wrong_byte_index = wrong_bytes.len() - 1;
        let mut wrong_byte = wrong_bytes[wrong_byte_index];
        // Break it gently (still in the valid '0' to '9' range)
        wrong_byte ^= 1;
        wrong_bytes[wrong_byte_index] = wrong_byte;

        let mut wrong_header = header.clone();
        wrong_header.work = prost::bytes::Bytes::from(wrong_bytes);
        invalid_fork_headers[wrong_header_index] = wrong_header.clone();

        // handling invalid fork headers
        let res = handle_btc_headers_from_babylon(&mut storage, &invalid_fork_headers);
        assert_eq!(
            res.unwrap_err(),
            BTCLightclientError::BTCWrongCumulativeWork(
                wrong_header_index,
                total_work(&header).unwrap(),
                total_work(&wrong_header).unwrap(),
            )
        );

        // ensure base and tip are eunchanged
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);
    }

    // btc_lc_fork_msg_accepted simulates initialization of BTC light client storage,
    // then insertion of a number of headers through a user execution message.
    // It checks the correctness of the fork choice rule for an accepted fork received through
    // the `handle_btc_headers_from_user` function.
    #[test]
    fn btc_lc_fork_msg_accepted() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // initialize with all headers
        init(&mut storage, &test_headers).unwrap();

        // ensure base and tip are set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);

        // get fork messages headers
        let test_fork_msg_headers = get_fork_msg_test_headers();

        // handling fork headers
        handle_btc_headers_from_user(&mut storage, &test_fork_msg_headers).unwrap();

        // ensure the base header is set
        let base_expected = test_headers.first().unwrap();
        let base_actual = get_base_header(&storage).unwrap();
        assert_eq!(*base_expected, base_actual);
        // ensure the tip btc header is set and is correct
        let tip_btc_expected: BlockHeader =
            test_fork_msg_headers.last().unwrap().try_into().unwrap();
        let tip_btc_actual: BlockHeader =
            babylon_bitcoin::deserialize(get_tip(&storage).unwrap().header.as_ref()).unwrap();
        assert_eq!(tip_btc_expected, tip_btc_actual);

        // ensure all initial headers are still inserted
        ensure_headers(&storage, &test_headers[..FORK_HEADER_HEIGHT as usize]);

        // ensure all forked btc headers are correctly inserted
        ensure_btc_headers(&storage, &test_fork_msg_headers);

        // check that the original forked headers have been removed from the hash-to-height map
        for header_expected in test_headers[FORK_HEADER_HEIGHT as usize..].iter() {
            assert!(get_header_height(&storage, header_expected.hash.as_ref()).is_err());
        }
    }
}
