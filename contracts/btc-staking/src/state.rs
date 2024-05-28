use derivative::Derivative;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_controllers::Admin;

use cw_storage_plus::{IndexedSnapshotMap, Item, Map, MultiIndex, Strategy};

use crate::fp_index::FinalityProviderIndexes;
use babylon_apis::btc_staking_api::HASH_SIZE;
use babylon_apis::btc_staking_api::{ActiveBtcDelegation, FinalityProvider};

pub(crate) const CONFIG: Item<Config> = Item::new("config");
pub(crate) const PARAMS: Item<Params> = Item::new("params");

/// Finality providers by their BTC public key
pub(crate) const FPS: Map<&str, FinalityProvider> = Map::new("fps");

/// Delegations by staking tx hash
pub(crate) const DELEGATIONS: Map<&[u8; HASH_SIZE], ActiveBtcDelegation> = Map::new("delegations");
/// Map of staking hashes by finality provider
pub(crate) const FP_DELEGATIONS: Map<&str, Vec<Vec<u8>>> = Map::new("fp_delegations");
/// Reverse map of finality providers by staking hash
pub(crate) const DELEGATION_FPS: Map<&[u8; HASH_SIZE], Vec<String>> = Map::new("delegation_fps");
// TODO: Map of staking hashes by delegator
// pub(crate) const STAKER_DELEGATIONS: Map<&str, Vec<Vec<u8>>> = Map::new("staker_delegations");

pub const FP_STATE_KEY: &str = "fp_state";
const FP_STATE_CHECKPOINTS: &str = "fp_state__checkpoints";
const FP_STATE_CHANGELOG: &str = "fp_state__changelog";
pub const FP_POWER_KEY: &str = "fp_state__power";
pub const ADMIN: Admin = Admin::new("admin");

/// Indexed snapshot map for finality providers.
///
/// This allows querying the map finality providers, sorted by their (aggregated) power.
/// The power index is a `MultiIndex`, as there can be multiple FPs with the same power.
///
/// The indexes are not snapshotted; only the current power is indexed at any given time.
pub fn fps<'a>(
) -> IndexedSnapshotMap<'a, &'a str, FinalityProviderState, FinalityProviderIndexes<'a>> {
    let indexes = FinalityProviderIndexes {
        power: MultiIndex::new(|_, fpi| fpi.power, FP_STATE_KEY, FP_POWER_KEY),
    };
    IndexedSnapshotMap::new(
        FP_STATE_KEY,
        FP_STATE_CHECKPOINTS,
        FP_STATE_CHANGELOG,
        Strategy::EveryBlock,
        indexes,
    )
}

/// Map of BTC height by block height
pub(crate) const BTC_HEIGHT: Map<u64, u64> = Map::new("btc_height");

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
    // min_slashing_tx_fee_sat is the minimum amount of tx fee (quantified / in Satoshi) needed for
    // the pre-signed slashing tx
    // pub min_slashing_tx_fee_sat: i64,
    // slashing_rate determines the portion of the staked amount to be slashed,
    // expressed as a decimal (e.g. 0.5 for 50%).
    // pub slashing_rate: Decimal,
}

/// Params define Consumer-selectable BTC staking parameters
// TODO: Add / enable param entries as needed
#[cw_serde]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Params {
    // min_commission_rate is the chain-wide minimum commission rate that a finality provider
    // can charge their delegators
    // pub min_commission_rate: Decimal,
    /// max_active_finality_providers is the maximum number of active finality providers in the
    /// BTC staking protocol
    #[derivative(Default(value = "100"))]
    pub max_active_finality_providers: u32,
}

#[cw_serde]
#[derive(Default)]
pub struct FinalityProviderState {
    /// Finality provider power, in satoshis
    pub power: u64,
}
