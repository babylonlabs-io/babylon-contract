use crate::error::ContractError;
use crate::msg::BlockVotesResponse;
use crate::state::config::{Config, ADMIN, CONFIG, IS_ENABLED};
use crate::state::finality::BLOCK_VOTES;
use crate::state::public_randomness::PUB_RAND_COMMITS;
use babylon_apis::finality_api::PubRandCommit;
use cosmwasm_std::Order::Descending;
use cosmwasm_std::{Deps, StdResult, Storage};
use cw_controllers::AdminResponse;

pub fn query_config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn query_block_votes(deps: Deps, height: u64, hash: String) -> StdResult<BlockVotesResponse> {
    // find all FPs that voted for this (height, hash) combination
    let fp_pubkey_hex_list = BLOCK_VOTES.load(deps.storage, (height, hash.as_bytes()))?;
    Ok(BlockVotesResponse { fp_pubkey_hex_list })
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

pub fn query_is_enabled(deps: Deps) -> StdResult<bool> {
    IS_ENABLED.load(deps.storage)
}

pub fn query_admin(deps: Deps) -> StdResult<AdminResponse> {
    ADMIN.query_admin(deps)
}
