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
use crate::utils::btc_light_client::verify_headers;
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
pub fn get_tip(storage: &mut dyn Storage) -> BtcHeaderInfo {
    let storage_tip = get_storage_tip(storage);
    let tip_bytes = storage_tip.get(KEY_TIP).unwrap();
    // NOTE: if init is successful, then tip header is guaranteed to be correct
    return BtcHeaderInfo::decode(tip_bytes.as_slice()).unwrap();
}

fn set_tip(storage: &mut dyn Storage, tip: &BtcHeaderInfo) {
    let mut storage_tip = get_storage_tip(storage);
    let tip_bytes = &tip.encode_to_vec();
    storage_tip.set(KEY_TIP, tip_bytes);
}

// insert_headers inserts BTC headers that have passed the
// verification to the header chain storages, including
// - insert all headers
// - insert all hash-to-height indices
fn insert_headers(storage: &mut dyn Storage, new_headers: &[BtcHeaderInfo]) {
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
pub fn get_header(
    storage: &mut dyn Storage,
    hash: &[u8],
) -> Result<BtcHeaderInfo, error::BTCLightclientError> {
    let storage_headers = get_storage_headers(storage);

    // try to find the header with the given hash
    let header_res = storage_headers.get(hash);
    if header_res.is_none() {
        return Err(error::BTCLightclientError::BTCHeaderNotFoundError {
            hash: hex::encode(hash),
        });
    }
    let header_bytes = header_res.unwrap();

    // try to decode the header
    let header_res = BtcHeaderInfo::decode(header_bytes.as_slice());
    if header_res.is_err() {
        return Err(error::BTCLightclientError::BTCHeaderDecodeError {});
    }

    return Ok(header_res.unwrap());
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
        babylon_bitcoin::deserialize(base_header.header.as_ref());
    if base_btc_header_res.is_err() {
        return Err(error::BTCLightclientError::BTCHeaderDecodeError {});
    }
    let base_btc_header = base_btc_header_res.unwrap();

    // verify the base header's pow
    if let Err(_) = babylon_bitcoin::pow::verify_header_pow(&btc_network, &base_btc_header) {
        return Err(error::BTCLightclientError::BTCHeaderError {});
    }

    // verify subsequent headers
    let new_headers = &headers[1..headers.len()];
    verify_headers(&btc_network, base_header, new_headers)?;

    // all good, set base header, insert all headers, and set tip

    // initialise base header
    // NOTE: not changeable in the future
    set_base_header(storage, base_header);
    // insert all headers
    insert_headers(storage, headers);
    // set tip header
    set_tip(storage, headers.last().unwrap());

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

    // decode the first header in these new headers
    let first_new_header = new_headers.first().unwrap();
    let first_new_btc_header_res: Result<babylon_bitcoin::BlockHeader, babylon_bitcoin::Error> =
        babylon_bitcoin::deserialize(first_new_header.header.as_ref());
    if first_new_btc_header_res.is_err() {
        return Err(error::BTCLightclientError::BTCHeaderDecodeError {});
    }
    let first_new_btc_header = first_new_btc_header_res.unwrap();

    // ensure the first header's previous header exists in KVStore
    // NOTE: prev_blockhash is in little endian
    let mut last_hash: Vec<u8> = first_new_btc_header.prev_blockhash.as_ref().into();
    last_hash.reverse(); // change to big endian
    let last_header = get_header(storage, &last_hash)?;

    // verify each new header after last_header iteratively
    verify_headers(&btc_network, &last_header, new_headers)?;

    // all good, append all headers to the BTC light client stores
    insert_headers(storage, &new_headers);

    // update tip
    let new_tip = new_headers.last().unwrap();
    set_tip(storage, &new_tip);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::mock_dependencies;
    use serde::{Deserialize, Serialize};
    use std::fs::File;
    use std::io::Read;

    const BTC_LC_TESTDATA: &str = "src/state/testdata/btclightclient.json";

    // intermediate structs for json -> BtcHeaderInfoSerde -> BtcHeaderInfo
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, Deserialize, Serialize)]
    pub struct BtcHeaderInfoSerde {
        pub header: String,
        pub hash: String,
        pub height: String,
        pub work: String,
    }

    impl From<BtcHeaderInfoSerde> for BtcHeaderInfo {
        fn from(a: BtcHeaderInfoSerde) -> Self {
            BtcHeaderInfo {
                header: hex::decode(a.header).unwrap().into(),
                hash: hex::decode(a.hash).unwrap().into(),
                height: a.height.parse::<u64>().unwrap(),
                work: a.work.into(),
            }
        }
    }

    // convert the json file to a vector of BtcHeaderInfo
    fn get_test_headers() -> Vec<BtcHeaderInfo> {
        let mut file = File::open(BTC_LC_TESTDATA).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let headers_serde: Vec<BtcHeaderInfoSerde> = serde_json::from_str(&contents).unwrap();
        let headers: Vec<BtcHeaderInfo> = headers_serde
            .into_iter()
            .rev() // from low height to high height
            .map(|a| BtcHeaderInfo::from(a))
            .collect();
        return headers;
    }

    // btc_lc_works simulates initialisation of BTC light client storage, then insertion of
    // a number of headers. It ensures that the correctness of initialisation/insertion upon
    // a list of correct BTC headers on Bitcoin mainnet.
    #[test]
    fn btc_lc_works() {
        let test_headers_vec = get_test_headers();
        let test_headers = test_headers_vec.as_slice();
        let deps = mock_dependencies();
        let mut storage = deps.storage;

        // set config first
        let w = 10 as usize;
        let cfg = super::super::config::Config {
            network: babylon_bitcoin::chain_params::Network::Mainnet,
            babylon_tag: b"bbn0".to_vec(),
            btc_confirmation_depth: 6,
            checkpoint_finalization_timeout: w as u64,
        };
        super::super::config::init(&mut storage, cfg);

        // testing initialisation with w+1 headers
        let test_init_headers: &[BtcHeaderInfo] = &test_headers[0..w + 1];
        init(&mut storage, test_init_headers).unwrap();

        // ensure tip is set
        let tip_expected = test_init_headers.last().unwrap();
        let tip_actual = get_tip(&mut storage);
        assert!(*tip_expected == tip_actual);
        // ensure base header is set
        let base_expected = test_init_headers.first().unwrap();
        let base_actual = get_base_header(&mut storage);
        assert!(*base_expected == base_actual);
        // ensure all headers are correctly inserted
        for header_expected in test_init_headers.iter() {
            let init_header_actual =
                get_header(&mut storage, header_expected.hash.as_ref()).unwrap();
            assert!(*header_expected == init_header_actual);

            let actual_height_be = get_storage_h2h(&mut storage)
                .get(header_expected.hash.as_ref())
                .unwrap();
            let actual_height_be_arr: [u8; 8] = actual_height_be.try_into().unwrap();
            let actual_height = u64::from_be_bytes(actual_height_be_arr);
            assert_eq!(header_expected.height, actual_height);
        }

        // handling subsequent headers
        let test_new_headers = &test_headers[w + 1..test_headers.len()];
        handle_btc_headers_from_babylon(&mut storage, test_new_headers).unwrap();

        // ensure tip is set
        let tip_expected = test_headers.last().unwrap();
        let tip_actual = get_tip(&mut storage);
        assert!(*tip_expected == tip_actual);
        // ensure all headers are correctly inserted
        for header_expected in test_new_headers.iter() {
            let init_header_actual =
                get_header(&mut storage, header_expected.hash.as_ref()).unwrap();
            assert!(*header_expected == init_header_actual);

            let actual_height_be = get_storage_h2h(&mut storage)
                .get(header_expected.hash.as_ref())
                .unwrap();
            let actual_height_be_arr: [u8; 8] = actual_height_be.try_into().unwrap();
            let actual_height = u64::from_be_bytes(actual_height_be_arr);
            assert_eq!(header_expected.height, actual_height);
        }
    }

    // TODO: more tests on different scenarios, e.g., random number of headers and conflicted headers
}
