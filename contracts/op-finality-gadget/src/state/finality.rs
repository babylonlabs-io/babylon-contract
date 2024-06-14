use cw_storage_plus::Map;

/// Map of signatures by block height and fp
pub(crate) const SIGNATURES: Map<(u64, &str), Vec<u8>> = Map::new("fp_sigs");
