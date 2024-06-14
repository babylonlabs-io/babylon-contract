use cw_controllers::Admin;
use cw_storage_plus::Item;

pub const ADMIN: Admin = Admin::new("admin");
pub const CONSUMER_CHAIN_ID: Item<String> = Item::new("consumer_chain_id");
