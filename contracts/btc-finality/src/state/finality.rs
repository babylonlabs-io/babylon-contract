use cosmwasm_schema::cw_serde;
use cw_storage_plus::{Item, Map};

use babylon_apis::finality_api::{Evidence, IndexedBlock};
use btc_staking::msg::FinalityProviderInfo;

/// Finality provider vote, with the signature and voting power
#[cw_serde]
pub struct Vote {
    pub signature: Vec<u8>,
    pub voting_power: u64,
}

/// Map of votes by block height and FP
pub const VOTES: Map<(u64, &str), Vote> = Map::new("fp_votes");

/// Map of blocks information by height
pub const BLOCKS: Map<u64, IndexedBlock> = Map::new("blocks");

/// Next height to finalise
pub const NEXT_HEIGHT: Item<u64> = Item::new("next_height");

/// `FP_SET` is the calculated list of the active finality providers by height
pub const FP_SET: Map<u64, Vec<FinalityProviderInfo>> = Map::new("fp_set");

/// Map of double signing evidence by FP and block height
pub const EVIDENCES: Map<(&str, u64), Evidence> = Map::new("evidences");
