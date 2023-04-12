//! Config is a singleton object in contract's storage

use cosmwasm_std::Storage;
use cosmwasm_storage::{singleton, singleton_read, ReadonlySingleton};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const KEY_CONFIG: &[u8] = b"config";

/// Config is a singleton object in contract's storage
// TODO: add necessary config entries to Config struct
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Config {
    pub network: babylon_bitcoin::chain_params::Network,
    pub btc_confirmation_depth: u64,
    pub checkpoint_finalization_timeout: u64,
}

/// init initialises the Config singleton object, which allows read/write
/// over the Config object
pub fn init(storage: &mut dyn Storage, cfg: Config) {
    let mut config = singleton(storage, KEY_CONFIG);
    config.save(&cfg).unwrap();
}

/// get returns the Config singleton object
pub fn get(storage: &dyn Storage) -> ReadonlySingleton<Config> {
    singleton_read(storage, KEY_CONFIG)
}
