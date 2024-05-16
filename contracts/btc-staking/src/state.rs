use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;

use cw_storage_plus::{Item, Map};

use babylon_apis::btc_staking_api::HASH_SIZE;
use babylon_apis::btc_staking_api::{ActiveBtcDelegation, FinalityProvider};

pub(crate) const CONFIG: Item<Config> = Item::new("config");

/// Finality providers by their BTC public key
pub(crate) const FPS: Map<&str, FinalityProvider> = Map::new("fps");

/// Delegations by staking tx hash
pub(crate) const DELEGATIONS: Map<&[u8; HASH_SIZE], ActiveBtcDelegation> = Map::new("delegations");
/// Map of staking hashes by finality provider
pub(crate) const FP_DELEGATIONS: Map<&str, Vec<Vec<u8>>> = Map::new("fp_delegations");
// TODO: Map of staking hashes by delegator
// pub(crate) const STAKER_DELEGATIONS: Map<&str, Vec<Vec<u8>>> = Map::new("staker_delegations");

// TODO: Add necessary config entries to Config struct
#[cw_serde]
pub struct Config {
    pub denom: String,
    pub babylon: Addr,
}
