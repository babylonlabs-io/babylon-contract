use cosmwasm_schema::cw_serde;
use cw_storage_plus::{IndexedSnapshotMap, Map, MultiIndex, Strategy};

use babylon_apis::btc_staking_api::{ActiveBtcDelegation, FinalityProvider, HASH_SIZE};

use crate::state::fp_index::FinalityProviderIndexes;

/// Finality providers by their BTC public key
pub(crate) const FPS: Map<&str, FinalityProvider> = Map::new("fps");

/// Delegations by staking tx hash
/// TODO: create a new DB object for BTC delegation
pub(crate) const DELEGATIONS: Map<&[u8; HASH_SIZE], ActiveBtcDelegation> = Map::new("delegations");
/// Map of staking hashes by finality provider
pub(crate) const FP_DELEGATIONS: Map<&str, Vec<Vec<u8>>> = Map::new("fp_delegations");
/// Reverse map of finality providers by staking hash
pub(crate) const DELEGATION_FPS: Map<&[u8; HASH_SIZE], Vec<String>> = Map::new("delegation_fps");

pub const FP_STATE_KEY: &str = "fp_state";
const FP_STATE_CHECKPOINTS: &str = "fp_state__checkpoints";
const FP_STATE_CHANGELOG: &str = "fp_state__changelog";
pub const FP_POWER_KEY: &str = "fp_state__power";

/// Indexed snapshot map for finality providers.
///
/// This allows querying the map finality providers, sorted by their (aggregated) power.
/// The power index is a `MultiIndex`, as there can be multiple FPs with the same power.
///
/// The indexes are not snapshotted; only the current power is indexed at any given time.
pub fn fps<'a>() -> IndexedSnapshotMap<&'a str, FinalityProviderState, FinalityProviderIndexes<'a>>
{
    let indexes = FinalityProviderIndexes {
        power: MultiIndex::new(|_, fp_state| fp_state.power, FP_STATE_KEY, FP_POWER_KEY),
    };
    IndexedSnapshotMap::new(
        FP_STATE_KEY,
        FP_STATE_CHECKPOINTS,
        FP_STATE_CHANGELOG,
        Strategy::EveryBlock,
        indexes,
    )
}

#[cw_serde]
#[derive(Default)]
pub struct FinalityProviderState {
    /// Finality provider power, in satoshis
    pub power: u64,
}
