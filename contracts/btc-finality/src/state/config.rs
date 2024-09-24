use derivative::Derivative;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;

use cw_controllers::Admin;
use cw_storage_plus::Item;

pub(crate) const CONFIG: Item<Config> = Item::new("config");
pub(crate) const PARAMS: Item<Params> = Item::new("params");
/// Storage for admin
pub(crate) const ADMIN: Admin = Admin::new("admin");

/// Config are Babylon-selectable BTC finality configuration
// TODO: Add / enable config entries as needed
#[cw_serde]
pub struct Config {
    pub babylon: Addr,
    pub staking: Addr,
}

// TODO: Add / enable param entries as needed
#[cw_serde]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Params {
    /// `max_active_finality_providers` is the maximum number of active finality providers in the
    /// BTC staking protocol
    #[derivative(Default(value = "100"))]
    pub max_active_finality_providers: u32,
    /// `min_pub_rand` is the minimum amount of public randomness each public randomness commitment
    /// should commit
    #[derivative(Default(value = "1"))]
    pub min_pub_rand: u64,
}
