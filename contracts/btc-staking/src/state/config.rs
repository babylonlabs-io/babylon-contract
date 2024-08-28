use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cosmwasm_std::Decimal;
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
    pub denom: String,
    pub babylon: Addr,
    // covenant_pks is the list of public keys held by the covenant committee each PK
    // follows encoding in BIP-340 spec on Bitcoin
    // pub covenant_pks: Vec<BIP340PubKey>,
    // covenant_quorum is the minimum number of signatures needed for the covenant multi-signature
    // pub covenant_quorum: u32,
}

/// Params define Consumer-selectable BTC staking parameters
// TODO: Add / enable param entries as needed
#[cw_serde]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Params {
    // `min_commission_rate` is the chain-wide minimum commission rate that a finality provider
    // can charge their delegators
    // pub min_commission_rate: Decimal,
    /// `max_active_finality_providers` is the maximum number of active finality providers in the
    /// BTC staking protocol
    #[derivative(Default(value = "100"))]
    pub max_active_finality_providers: u32,
    /// `min_pub_rand` is the minimum amount of public randomness each public randomness commitment
    /// should commit
    #[derivative(Default(value = "1"))]
    pub min_pub_rand: u64,
    /// `slashing_address` is the address that the slashed BTC goes to.
    /// The address is in string format on Bitcoin.
    #[derivative(Default(value = "String::from(\"SMPJunctnV4LunQRk37CuFeWeU9iBDoZwx\")"))]
    pub slashing_address: String,
    /// `min_slashing_tx_fee_sat` is the minimum amount of tx fee (quantified in Satoshi) needed for
    /// the pre-signed slashing tx
    #[derivative(Default(value = "1000"))]
    pub min_slashing_tx_fee_sat: u64,
    /// `slashing_rate` determines the portion of the staked amount to be slashed,
    /// expressed as a decimal (e.g. 0.5 for 50%).
    #[derivative(Default(value = "Decimal::percent(10)"))]
    pub slashing_rate: Decimal,
}
