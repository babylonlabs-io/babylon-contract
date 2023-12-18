use cosmwasm_schema::cw_serde;
use cw_storage_plus::Item;

pub(crate) const CONFIG: Item<Config> = Item::new("config");

// TODO: Add necessary config entries to Config struct
#[cw_serde]
pub struct Config {
    pub network: babylon_bitcoin::chain_params::Network,
    pub babylon_tag: Vec<u8>,
    pub btc_confirmation_depth: u64,
    pub checkpoint_finalization_timeout: u64,
    // notify_cosmos_zone indicates whether to send Cosmos zone messages notifying BTC-finalised headers
    // NOTE: if set true, then the Cosmos zone needs to integrate the corresponding message handler as well
    pub notify_cosmos_zone: bool,
}
