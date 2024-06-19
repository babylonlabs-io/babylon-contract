use crate::msg::QueryBlockFinalizedResponse;
use crate::state::config::{Config, CONFIG};
use crate::state::finality::BLOCK_VOTES;
use cosmwasm_std::{Deps, StdResult, Timestamp};
use std::collections::HashSet;

pub fn query_config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn query_block_finalized(
    deps: Deps,
    // height, hash and timestamp for the L2 block
    height: u64,
    hash: String,
    _timestamp: Timestamp,
) -> StdResult<QueryBlockFinalizedResponse> {
    // find all FPs that voted for this (height, hash) combination
    let _block_votes_fp_set = BLOCK_VOTES
        .may_load(deps.storage, (height, hash.as_bytes()))?
        .unwrap_or_else(HashSet::new);

    /*
      - convert the timestamp to the closest BTC height
      - for each FP, get its voting power at the specific BTC height via gRPC and sum up
      - get the total voting power reistered for the consumer chain
      - caculate the quorum
      - return true if P/S > 2/3; otherwise return false
    */

    Ok(QueryBlockFinalizedResponse { finalized: true })
}
