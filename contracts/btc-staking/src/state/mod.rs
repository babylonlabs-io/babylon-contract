pub mod config;
pub mod finality;
pub mod public_randomness;
pub mod staking;

mod fp_index;

use cw_storage_plus::Map;

/// Map of BTC height by block height
pub(crate) const BTC_HEIGHT: Map<u64, u64> = Map::new("btc_height");
