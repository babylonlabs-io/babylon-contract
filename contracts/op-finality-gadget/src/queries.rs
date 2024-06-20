use crate::error::ContractError;
use crate::msg::BlockFinalizedResponse;
use crate::state::config::{Config, CONFIG};
use crate::state::finality::BLOCK_VOTES;
use crate::state::public_randomness::PUB_RAND_COMMITS;
use babylon_apis::finality_api::PubRandCommit;
use cosmwasm_std::Order::Descending;
use cosmwasm_std::{Deps, StdResult, Storage};
use std::collections::HashSet;

pub fn query_config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn query_block_finalized(
    deps: Deps,
    // height, hash and timestamp for the L2 block
    height: u64,
    hash: String,
    _btc_height: u64,
) -> StdResult<BlockFinalizedResponse> {
    // find all FPs that voted for this (height, hash) combination
    let _block_votes_fp_set = BLOCK_VOTES
        .may_load(deps.storage, (height, hash.as_bytes()))?
        .unwrap_or_else(HashSet::new);

    /*
      - for each FP, get its voting power at the specific BTC height via custom query and sum up
      - get the total voting power reistered for the consumer chain
      - caculate the quorum
      - return true if P/S > 2/3; otherwise return false
    */

    Ok(BlockFinalizedResponse { finalized: true })
}

// Copied from contracts/btc-staking/src/state/public_randomness.rs
pub fn query_last_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
) -> Result<PubRandCommit, ContractError> {
    let res = PUB_RAND_COMMITS
        .prefix(fp_btc_pk_hex)
        .range_raw(storage, None, None, Descending)
        .take(1)
        .map(|item| {
            let (_, value) = item?;
            Ok(value)
        })
        .collect::<StdResult<Vec<_>>>()?;
    if res.is_empty() {
        Err(ContractError::MissingPubRandCommit(
            fp_btc_pk_hex.to_string(),
            0,
        ))
    } else {
        Ok(res[0].clone())
    }
}
