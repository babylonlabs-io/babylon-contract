use cosmwasm_std::testing::{mock_dependencies, MockStorage};
use cosmwasm_std::Storage;

use crate::state::config::{Config, CONFIG};
use babylon_bitcoin::chain_params::Network;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use test_utils::{get_btc_lc_fork_headers as get_fork_headers, get_btc_lc_headers as get_headers};

pub(crate) fn setup(storage: &mut dyn Storage) -> u32 {
    // set config first
    let w: u32 = 2;
    let cfg = Config {
        network: Network::Regtest,
        btc_confirmation_depth: 1,
    };
    CONFIG.save(storage, &cfg).unwrap();
    w
}

pub(crate) fn mock_storage() -> MockStorage {
    let deps = mock_dependencies();
    deps.storage
}

pub(crate) fn get_btc_lc_headers() -> Vec<BtcHeaderInfo> {
    get_headers()
}

pub(crate) fn get_btc_lc_fork_headers() -> Vec<BtcHeaderInfo> {
    get_fork_headers()
}
