use cw_storage_plus::{Item, Map};
use std::collections::HashSet;

/// Map of signatures by block height and fp
pub(crate) const SIGNATURES: Map<(u64, &str), Vec<u8>> = Map::new("fp_sigs");

/// Map of (block height, block hash) tuples to the list of fps that voted for this combination
pub(crate) const BLOCK_VOTES: Map<(u64, &[u8]), HashSet<String>> = Map::new("block_hashes");

/// Ordered list of forked blocks [(start_height_1, end_height_1), (start_height_2, end_height_2), ...]
pub(crate) const FORKED_BLOCKS: Item<Vec<(u64, u64)>> = Item::new("forked_blocks");
