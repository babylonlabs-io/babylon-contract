//! state is the module that manages smart contract's system state

// root-level prefixes/keys for KVStore
pub(crate) const KEY_CONFIG: &[u8] = &[0];
pub(crate) const PREFIX_BTC_LIGHT_CLIENT: &[u8] = &[1];
pub(crate) const PREFIX_BABYLON_EPOCH_CHAIN: &[u8] = &[2];
pub(crate) const PREFIX_CZ_HEADER_CHAIN: &[u8] = &[3];

pub mod babylon_epoch_chain;
pub mod btc_light_client;
pub mod config;
pub mod cz_header_chain;
