use babylon_apis::finality_api::PubRandCommit;
use cosmwasm_std::Order::Descending;
use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::{Bound, Map};

use crate::error::ContractError;

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
