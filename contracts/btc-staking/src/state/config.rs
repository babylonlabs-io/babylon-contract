use babylon_bitcoin::chain_params::Network;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;

use cw_controllers::Admin;
use cw_storage_plus::Item;
use derivative::Derivative;

pub(crate) const CONFIG: Item<Config> = Item::new("config");
pub(crate) const PARAMS: Item<Params> = Item::new("params");
/// Storage for admin
pub(crate) const ADMIN: Admin = Admin::new("admin");

/// Config are Babylon-selectable BTC staking configuration
// TODO: Add / enable config entries as needed
#[cw_serde]
pub struct Config {
    pub babylon: Addr,
}

/// Params define Consumer-selectable BTC staking parameters
// TODO: Add / enable param entries as needed
#[cw_serde]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Params {
    // covenant_pks is the list of public keys held by the covenant committee each PK
    // follows encoding in BIP-340 spec on Bitcoin
    pub covenant_pks: Vec<String>,
    // covenant_quorum is the minimum number of signatures needed for the covenant multi-signature
    pub covenant_quorum: u32,
    #[derivative(Default(value = "Network::Regtest"))]
    // ntc_network is the network the BTC staking protocol is running on
    pub btc_network: Network,
    // `min_commission_rate` is the chain-wide minimum commission rate that a finality provider
    // can charge their delegators
    // pub min_commission_rate: Decimal,
    /// `slashing_address` is the address that the slashed BTC goes to.
    /// The address is in string format on Bitcoin.
    #[derivative(Default(value = "String::from(\"n4cV57jePmAAue2WTTBQzH3k3R2rgWBQwY\")"))]
    pub slashing_address: String,
    /// `min_slashing_tx_fee_sat` is the minimum amount of tx fee (quantified in Satoshi) needed for
    /// the pre-signed slashing tx
    #[derivative(Default(value = "1000"))]
    pub min_slashing_tx_fee_sat: u64,
    /// `slashing_rate` determines the portion of the staked amount to be slashed,
    /// expressed as a decimal (e.g. 0.5 for 50%).
    #[derivative(Default(value = "String::from(\"0.1\")"))]
    pub slashing_rate: String,
}
