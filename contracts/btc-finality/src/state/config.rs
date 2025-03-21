use derivative::Derivative;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Decimal};

use cw_controllers::Admin;
use cw_storage_plus::Item;

pub(crate) const CONFIG: Item<Config> = Item::new("config");
pub(crate) const PARAMS: Item<Params> = Item::new("params");
/// Storage for admin
pub(crate) const ADMIN: Admin = Admin::new("admin");

/// Config are Babylon-selectable BTC finality configuration
#[cw_serde]
pub struct Config {
    pub denom: String,
    pub blocks_per_year: u64,
    pub babylon: Addr,
    pub staking: Addr,
}

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
    /// `finality_inflation_rate` is the inflation rate for finality providers' block rewards
    #[derivative(Default(value = "Decimal::permille(35)"))] // 3.5 % by default
    pub finality_inflation_rate: Decimal,
    /// `epoch_length` is the number of blocks that defines an epoch
    #[derivative(Default(value = "50"))] // 50 * ~6.5s = ~5min
    pub epoch_length: u64,
}
