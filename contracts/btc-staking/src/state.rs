use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::Item;

pub(crate) const CONFIG: Item<Config> = Item::new("config");

// TODO: Add necessary config entries to Config struct
#[cw_serde]
pub struct Config {
    pub denom: String,
    pub babylon: Addr,
}
