use cosmwasm_schema::cw_serde;
use cw_controllers::Admin;
use cw_storage_plus::Item;

pub const ADMIN: Admin = Admin::new("admin");
pub const CONFIG: Item<Config> = Item::new("config");

/// Config are OP finality gadget's configuration
#[cw_serde]
pub struct Config {
    pub consumer_id: String,
    // activated_height is the consumer chain block height at which the finality gadget is activated
    pub activated_height: u64,
}
