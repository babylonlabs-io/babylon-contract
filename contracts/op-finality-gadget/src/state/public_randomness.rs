use crate::error::ContractError;
use babylon_apis::finality_api::PubRandCommit;
use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::{Bound, Map};

/// Map of public randomness commitments by fp and block height
pub(crate) const PUB_RAND_COMMITS: Map<(&str, u64), PubRandCommit> = Map::new("fp_pub_rand_commit");
/// Map of public randomness values by fp and block height
pub(crate) const PUB_RAND_VALUES: Map<(&str, u64), Vec<u8>> = Map::new("fp_pub_rand");

// Copied from contracts/btc-staking/src/state/public_randomness.rs
pub fn get_pub_rand_commit_for_height(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
    height: u64,
) -> Result<PubRandCommit, ContractError> {
    let end_at = Some(Bound::inclusive(height));
    let res = PUB_RAND_COMMITS
        .prefix(fp_btc_pk_hex)
        .range_raw(storage, None, end_at, Descending)
        .filter(|item| {
            match item {
                Ok((_, value)) => value.in_range(height),
                Err(_) => true, // if we can't parse, we keep it
            }
        })
        .take(1)
        .map(|item| {
            let (_, value) = item?;
            Ok(value)
        })
        .collect::<StdResult<Vec<_>>>()?;
    if res.is_empty() {
        Err(ContractError::MissingPubRandCommit(
            fp_btc_pk_hex.to_string(),
            height,
        ))
    } else {
        Ok(res[0].clone())
    }
}

// Copied from contracts/btc-staking/src/state/public_randomness.rs
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

pub fn get_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
    start_after: Option<u64>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<Vec<PubRandCommit>, ContractError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after.map(Bound::exclusive);
    let (start, end, order) = if reverse.unwrap_or(false) {
        (None, start_after, Descending)
    } else {
        (start_after, None, Ascending)
    };
    let res = PUB_RAND_COMMITS
        .prefix(fp_btc_pk_hex)
        .range_raw(storage, start, end, order)
        .take(limit)
        .map(|item| {
            let (_, value) = item?;
            Ok(value)
        })
        .collect::<StdResult<Vec<_>>>()?;

    // Return the results or an empty vector if no results found
    Ok(res)
}
