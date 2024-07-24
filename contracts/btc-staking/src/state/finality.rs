use babylon_apis::finality_api::{Evidence, IndexedBlock};
use cw_storage_plus::{Item, Map};

/// Map of signatures by block height and FP
pub(crate) const SIGNATURES: Map<(u64, &str), Vec<u8>> = Map::new("fp_sigs");

/// Map of blocks information by height
pub(crate) const BLOCKS: Map<u64, IndexedBlock> = Map::new("blocks");

/// Next height to finalise
pub(crate) const NEXT_HEIGHT: Item<u64> = Item::new("next_height");

/// Map of double signing evidence by FP and block height
pub(crate) const EVIDENCES: Map<(&str, u64), Evidence> = Map::new("evidences");
