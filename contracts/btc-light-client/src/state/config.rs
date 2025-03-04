use cosmwasm_schema::cw_serde;
use cosmwasm_std::StdResult;
use cw_storage_plus::Item;

#[cw_serde]
pub struct Config {
    pub network: babylon_bitcoin::chain_params::Network,
    pub btc_confirmation_depth: u32,
}

pub const CONFIG: Item<Config> = Item::new("config");
