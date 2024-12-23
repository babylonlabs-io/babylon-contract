use babylon_apis::finality_api::Evidence;
use cw_storage_plus::Map;
use std::collections::HashSet;

/// Map of signatures by block height and fp
pub(crate) const SIGNATURES: Map<(u64, &str), Vec<u8>> = Map::new("fp_sigs");

/// Map of block hashes by block height and fp
pub(crate) const BLOCK_HASHES: Map<(u64, &str), Vec<u8>> = Map::new("block_hashes");

/// Map of (block height, block hash) tuples to the list of fps that voted for this combination
pub(crate) const BLOCK_VOTES: Map<(u64, &[u8]), HashSet<String>> = Map::new("block_votes");

/// Map of evidence by block height and fp
pub(crate) const EVIDENCES: Map<(u64, &str), Evidence> = Map::new("evidences");
