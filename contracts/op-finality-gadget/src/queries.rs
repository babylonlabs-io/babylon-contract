use crate::error::ContractError;
use crate::state::config::{Config, ADMIN, CONFIG, IS_ENABLED};
use crate::state::finality::{BLOCK_VOTES, FORKED_BLOCKS};
use crate::state::public_randomness::get_pub_rand_commit;
use babylon_apis::finality_api::PubRandCommit;
use cosmwasm_std::{Deps, StdResult, Storage};
use cw_controllers::AdminResponse;
use std::cmp::{max, min};
use std::collections::HashSet;

pub fn query_config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn query_block_voters(
    deps: Deps,
    height: u64,
    hash: String,
) -> Result<Option<HashSet<String>>, ContractError> {
    let block_hash_bytes: Vec<u8> = hex::decode(&hash).map_err(ContractError::HexError)?;
    // find all FPs that voted for this (height, hash) combination
    let fp_pubkey_hex_list = BLOCK_VOTES
        .may_load(deps.storage, (height, &block_hash_bytes))
        .map_err(|e| {
            ContractError::QueryBlockVoterError(
                height,
                hash.clone(),
                format!("Original error: {:?}", e),
            )
        })?;
    Ok(fp_pubkey_hex_list)
}

pub fn query_first_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
) -> Result<Option<PubRandCommit>, ContractError> {
    let res = get_pub_rand_commit(storage, fp_btc_pk_hex, None, Some(1), Some(false))?;
    Ok(res.into_iter().next())
}

pub fn query_last_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
) -> Result<Option<PubRandCommit>, ContractError> {
    let res = get_pub_rand_commit(storage, fp_btc_pk_hex, None, Some(1), Some(true))?;
    Ok(res.into_iter().next())
}

pub fn query_is_block_forked(deps: Deps, height: u64) -> StdResult<bool> {
    // loop over forked blocks, starting from last entry
    let forked_blocks = FORKED_BLOCKS.load(deps.storage)?;
    for (start, end) in forked_blocks.iter().rev() {
        // if block is in range of any forked block, return true
        if height >= *start && height <= *end {
            return Ok(true);
        }
        // terminate early once we reach a forked block range lower than the queried block
        if height < *start {
            break;
        }
    }
    Ok(false)
}

pub fn query_forked_blocks_in_range(
    deps: Deps,
    start: u64,
    end: u64,
) -> StdResult<Vec<(u64, u64)>> {
    // loop over forked blocks, starting from last entry
    let mut block_ranges = Vec::new();
    let forked_blocks = FORKED_BLOCKS.load(deps.storage)?;
    for (fork_start, fork_end) in forked_blocks.iter().rev() {
        // append any overlapping forked block ranges to the list, moving cursor forward
        let overlap_start = max(*fork_start, start);
        let overlap_end = min(*fork_end, end);
        if overlap_start <= overlap_end {
            block_ranges.push((overlap_start, overlap_end));
        }
        // terminate early once we reach a forked block range lower than the queried block
        if *fork_start < start {
            break;
        }
    }
    Ok(block_ranges)
}

pub fn query_is_enabled(deps: Deps) -> StdResult<bool> {
    IS_ENABLED.load(deps.storage)
}

pub fn query_admin(deps: Deps) -> StdResult<AdminResponse> {
    ADMIN.query_admin(deps)
}
