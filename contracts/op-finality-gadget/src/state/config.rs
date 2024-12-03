use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_controllers::Admin;
use cw_storage_plus::Item;

pub const ADMIN: Admin = Admin::new("admin");
pub const CONFIG: Item<Config> = Item::new("config");
// if the finality gadget is disabled, it will always return true for the is finalized query
pub const IS_ENABLED: Item<bool> = Item::new("is_enabled");

/// Config are OP finality gadget's configuration
#[cw_serde]
pub struct Config {
    pub consumer_id: String,
    pub consumer_name: Option<String>,
    pub consumer_description: Option<String>,
    pub babylon: Addr,
}
