use cosmwasm_std::testing::mock_dependencies;
use cosmwasm_std::Storage;

use crate::state::config::{Config, CONFIG};
use babylon_bitcoin::chain_params::Network;

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

pub(crate) fn mock_storage() -> Box<dyn Storage> {
    let deps = mock_dependencies();
    Box::new(deps.storage)
}
