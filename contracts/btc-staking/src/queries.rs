use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::Txid;

use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{Deps, Order, StdResult};
use cw_storage_plus::Bound;

use babylon_apis::btc_staking_api::{ActiveBtcDelegation, FinalityProvider};
use babylon_apis::finality_api::IndexedBlock;

use crate::error::ContractError;
use crate::msg::{
    ActivatedHeightResponse, BlocksResponse, BtcDelegationsResponse, DelegationsByFPResponse,
    FinalityProviderInfo, FinalityProvidersByPowerResponse, FinalityProvidersResponse,
    FinalitySignatureResponse,
};
use crate::state::config::{Config, Params};
use crate::state::config::{CONFIG, PARAMS};
use crate::state::finality::BLOCKS;
use crate::state::staking::{
    fps, FinalityProviderState, ACTIVATED_HEIGHT, DELEGATIONS, FPS, FP_DELEGATIONS,
};

pub fn config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn params(deps: Deps) -> StdResult<Params> {
    PARAMS.load(deps.storage)
}

pub fn finality_provider(deps: Deps, btc_pk_hex: String) -> StdResult<FinalityProvider> {
    FPS.load(deps.storage, &btc_pk_hex)
}

// Settings for pagination
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

pub fn finality_providers(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<FinalityProvidersResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after.as_ref().map(|s| Bound::exclusive(&**s));
    let fps = FPS
        .range_raw(deps.storage, start_after, None, Order::Ascending)
        .take(limit)
        .map(|item| item.map(|(_, v)| v))
        .collect::<StdResult<Vec<FinalityProvider>>>()?;
    Ok(FinalityProvidersResponse { fps })
}

/// Get the delegation info by staking tx hash.
/// `staking_tx_hash_hex`: The (reversed) staking tx hash, in hex
pub fn delegation(
    deps: Deps,
    staking_tx_hash_hex: String,
) -> Result<ActiveBtcDelegation, ContractError> {
    let staking_tx_hash = Txid::from_str(&staking_tx_hash_hex)?;
    Ok(DELEGATIONS.load(deps.storage, staking_tx_hash.as_ref())?)
}

/// Get list of delegations.
/// `start_after`: The (reversed) associated staking tx hash of the delegation in hex, if provided.
/// `active`: List only active delegations if true, otherwise list all delegations.
pub fn delegations(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
    active: Option<bool>,
) -> Result<BtcDelegationsResponse, ContractError> {
    let active = active.unwrap_or_default();
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after
        .as_ref()
        .map(|s| Txid::from_str(s))
        .transpose()?;
    let start_after = start_after.as_ref().map(|s| s.as_ref());
    let start_after = start_after.map(Bound::exclusive);
    let delegations = DELEGATIONS
        .range_raw(deps.storage, start_after, None, Order::Ascending)
        .filter(|item| {
            if let Ok((_, del)) = item {
                !active || del.is_active()
            } else {
                true // don't filter errors
            }
        })
        .take(limit)
        .map(|item| item.map(|(_, v)| v))
        .collect::<Result<Vec<ActiveBtcDelegation>, _>>()?;
    Ok(BtcDelegationsResponse { delegations })
}

/// Delegation hashes by FP query.
///
/// `btc_pk_hex`: The BTC public key of the finality provider, in hex
pub fn delegations_by_fp(
    deps: Deps,
    btc_pk_hex: String,
) -> Result<DelegationsByFPResponse, ContractError> {
    let tx_hashes = FP_DELEGATIONS.load(deps.storage, &btc_pk_hex)?;
    let tx_hashes = tx_hashes
        .iter()
        .map(|h| Ok(Txid::from_slice(h)?.to_string()))
        .collect::<Result<_, ContractError>>()?;
    Ok(DelegationsByFPResponse { hashes: tx_hashes })
}

/// Active / all delegations by FP convenience query.
///
/// This is an alternative to `delegations_by_fp` that returns the actual delegations instead of
/// just the hashes.
///
/// `btc_pk_hex`: The BTC public key of the finality provider, in hex.
/// `active` is a filter to return only active delegations
pub fn active_delegations_by_fp(
    deps: Deps,
    btc_pk_hex: String,
    active: bool,
) -> Result<BtcDelegationsResponse, ContractError> {
    let tx_hashes = FP_DELEGATIONS.load(deps.storage, &btc_pk_hex)?;
    let delegations = tx_hashes
        .iter()
        .map(|h| Ok(DELEGATIONS.load(deps.storage, Txid::from_slice(h)?.as_ref())?))
        .filter(|item| {
            if let Ok(del) = item {
                !active || del.is_active()
            } else {
                true // don't filter errors
            }
        })
        .collect::<Result<Vec<_>, ContractError>>()?;
    Ok(BtcDelegationsResponse { delegations })
}

pub fn finality_provider_info(
    deps: Deps,
    btc_pk_hex: String,
    height: Option<u64>,
) -> StdResult<FinalityProviderInfo> {
    let fp_state = match height {
        Some(h) => fps().may_load_at_height(deps.storage, &btc_pk_hex, h),
        None => fps().may_load(deps.storage, &btc_pk_hex),
    }?
    .unwrap_or_default();

    Ok(FinalityProviderInfo {
        btc_pk_hex,
        power: fp_state.power,
    })
}

pub fn finality_providers_by_power(
    deps: Deps,
    start_after: Option<FinalityProviderInfo>,
    limit: Option<u32>,
) -> StdResult<FinalityProvidersByPowerResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = start_after.map(|fpp| Bound::exclusive((fpp.power, fpp.btc_pk_hex.clone())));
    let fps = fps()
        .idx
        .power
        .range(deps.storage, None, start, Order::Descending)
        .take(limit)
        .map(|item| {
            let (btc_pk_hex, FinalityProviderState { power }) = item?;
            Ok(FinalityProviderInfo { btc_pk_hex, power })
        })
        .collect::<StdResult<Vec<_>>>()?;

    Ok(FinalityProvidersByPowerResponse { fps })
}

pub fn finality_signature(
    deps: Deps,
    btc_pk_hex: String,
    height: u64,
) -> Result<FinalitySignatureResponse, ContractError> {
    let sig = crate::state::finality::SIGNATURES.load(deps.storage, (height, &btc_pk_hex))?;
    Ok(FinalitySignatureResponse { signature: sig })
}

pub fn activated_height(deps: Deps) -> Result<ActivatedHeightResponse, ContractError> {
    let activaed_height = ACTIVATED_HEIGHT.may_load(deps.storage)?.unwrap_or_default();
    Ok(ActivatedHeightResponse {
        height: activaed_height,
    })
}

pub fn block(deps: Deps, height: u64) -> StdResult<IndexedBlock> {
    BLOCKS.load(deps.storage, height)
}

/// Get list of blocks.
/// `start_after`: The height to start after, if any.
/// `finalised`: List only finalised blocks if true, otherwise list all blocks.
/// `reverse`: List in descending order if present and true, otherwise in ascending order.
pub fn blocks(
    deps: Deps,
    start_after: Option<u64>,
    limit: Option<u32>,
    finalised: Option<bool>,
    reverse: Option<bool>,
) -> Result<BlocksResponse, ContractError> {
    let finalised = finalised.unwrap_or_default();
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after.map(Bound::exclusive);
    let (start, end, order) = if reverse.unwrap_or(false) {
        (None, start_after, Descending)
    } else {
        (start_after, None, Ascending)
    };
    let blocks = BLOCKS
        .range_raw(deps.storage, start, end, order)
        .filter(|item| {
            if let Ok((_, block)) = item {
                !finalised || block.finalized
            } else {
                true // don't filter errors
            }
        })
        .take(limit)
        .map(|item| item.map(|(_, v)| v))
        .collect::<Result<Vec<IndexedBlock>, _>>()?;
    Ok(BlocksResponse { blocks })
}

#[cfg(test)]
mod tests {
    use bitcoin::Transaction;

    use cosmwasm_std::storage_keys::namespace_with_key;
    use cosmwasm_std::testing::message_info;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::StdError::NotFound;
    use cosmwasm_std::{from_json, Binary, Storage};

    use babylon_apis::btc_staking_api::{FinalityProvider, UnbondedBtcDelegation};

    use crate::contract::tests::create_new_finality_provider;
    use crate::contract::{execute, instantiate};
    use crate::error::ContractError;
    use crate::finality::tests::mock_env_height;
    use crate::msg::{ExecuteMsg, FinalityProviderInfo, InstantiateMsg};
    use crate::state::staking::{FinalityProviderState, FP_STATE_KEY};

    const CREATOR: &str = "creator";

    #[test]
    fn test_finality_providers() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Add a couple finality providers
        let new_fp1 = create_new_finality_provider(1);
        let new_fp2 = create_new_finality_provider(2);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone(), new_fp2.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query finality providers
        let fps = crate::queries::finality_providers(deps.as_ref(), None, None)
            .unwrap()
            .fps;
        let fp1 = FinalityProvider::from(&new_fp1);
        let fp2 = FinalityProvider::from(&new_fp2);
        assert_eq!(fps.len(), 2);
        assert_eq!(fps[0], fp1);
        assert_eq!(fps[1], fp2);

        // Query finality providers with limit
        let fps = crate::queries::finality_providers(deps.as_ref(), None, Some(1))
            .unwrap()
            .fps;
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0], fp1);

        // Query finality providers with start_after
        let fps = crate::queries::finality_providers(deps.as_ref(), Some("f1".to_string()), None)
            .unwrap()
            .fps;
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0], fp2);
    }

    #[test]
    fn test_delegations() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Add a couple finality providers
        let new_fp1 = create_new_finality_provider(1);
        let new_fp2 = create_new_finality_provider(2);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone(), new_fp2.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a couple delegations
        let del1 = crate::contract::tests::get_derived_btc_delegation(1, &[1]);
        let del2 = crate::contract::tests::get_derived_btc_delegation(2, &[2]);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query delegations
        let dels = crate::queries::delegations(deps.as_ref(), None, None, None)
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 2);
        assert_eq!(dels[0], del1);
        assert_eq!(dels[1], del2);

        // Query delegations with limit
        let dels = crate::queries::delegations(deps.as_ref(), None, Some(1), None)
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0], del1);

        // Query delegations with start_after
        let staking_tx: Transaction = bitcoin::consensus::deserialize(&del1.staking_tx).unwrap();
        let staking_tx_hash = staking_tx.txid();
        let staking_tx_hash_hex = staking_tx_hash.to_string();
        let dels =
            crate::queries::delegations(deps.as_ref(), Some(staking_tx_hash_hex), None, None)
                .unwrap()
                .delegations;

        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0], del2);
    }

    #[test]
    fn test_active_delegations() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Add a finality provider
        let new_fp1 = create_new_finality_provider(1);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a couple delegations
        let del1 = crate::contract::tests::get_derived_btc_delegation(1, &[1]);
        let del2 = crate::contract::tests::get_derived_btc_delegation(2, &[1]);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query only active delegations
        let dels = crate::queries::delegations(deps.as_ref(), None, None, Some(true))
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 2);
        assert_eq!(dels[0], del1);
        assert_eq!(dels[1], del2);

        // Unbond the second delegation
        // Compute staking tx hash
        let staking_tx: Transaction = bitcoin::consensus::deserialize(&del2.staking_tx).unwrap();
        let staking_tx_hash = staking_tx.txid();
        let staking_tx_hash_hex = staking_tx_hash.to_string();
        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![UnbondedBtcDelegation {
                staking_tx_hash: staking_tx_hash_hex,
                unbonding_tx_sig: Binary::new(vec![0x01, 0x02, 0x03]),
            }],
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query only active delegations
        let dels = crate::queries::delegations(deps.as_ref(), None, None, Some(true))
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0], del1);

        // Query all delegations (with active set to false)
        let dels = crate::queries::delegations(deps.as_ref(), None, None, Some(false))
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 2);

        // Query all delegations (without active set)
        let dels = crate::queries::delegations(deps.as_ref(), None, None, None)
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 2);
    }

    #[test]
    fn test_delegations_by_fp() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Add a couple finality providers
        let new_fp1 = create_new_finality_provider(1);
        let new_fp2 = create_new_finality_provider(2);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone(), new_fp2.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a couple delegations
        let del1 = crate::contract::tests::get_derived_btc_delegation(1, &[1]);
        let del2 = crate::contract::tests::get_derived_btc_delegation(2, &[2]);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query delegations by finality provider
        let dels1 = crate::queries::delegations_by_fp(deps.as_ref(), "f1".to_string())
            .unwrap()
            .hashes;
        assert_eq!(dels1.len(), 1);
        let dels2 = crate::queries::delegations_by_fp(deps.as_ref(), "f2".to_string())
            .unwrap()
            .hashes;
        assert_eq!(dels2.len(), 1);
        assert_ne!(dels1[0], dels2[0]);
        let err = crate::queries::delegations_by_fp(deps.as_ref(), "f3".to_string()).unwrap_err();
        assert!(matches!(err, ContractError::Std(NotFound { .. })));
    }

    #[test]
    fn test_active_delegations_by_fp() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Add a finality provider
        let new_fp1 = create_new_finality_provider(1);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a couple delegations
        let mut del1 = crate::contract::tests::get_derived_btc_delegation(1, &[1]);
        let mut del2 = crate::contract::tests::get_derived_btc_delegation(2, &[1]);

        // Adjust staking amounts
        del1.total_sat = 100;
        del2.total_sat = 200;

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query all delegations by finality provider
        let dels1 =
            crate::queries::active_delegations_by_fp(deps.as_ref(), "f1".to_string(), false)
                .unwrap()
                .delegations;
        assert_eq!(dels1.len(), 2);

        // Query active delegations by finality provider
        let dels1 = crate::queries::active_delegations_by_fp(deps.as_ref(), "f1".to_string(), true)
            .unwrap()
            .delegations;
        assert_eq!(dels1.len(), 2);

        // Unbond the first delegation
        // Compute staking tx hash
        let staking_tx: Transaction = bitcoin::consensus::deserialize(&del1.staking_tx).unwrap();
        let staking_tx_hash = staking_tx.txid();
        let staking_tx_hash_hex = staking_tx_hash.to_string();
        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![UnbondedBtcDelegation {
                staking_tx_hash: staking_tx_hash_hex,
                unbonding_tx_sig: Binary::new(vec![0x01, 0x02, 0x03]),
            }],
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query all delegations by finality provider
        let dels1 =
            crate::queries::active_delegations_by_fp(deps.as_ref(), "f1".to_string(), false)
                .unwrap()
                .delegations;
        assert_eq!(dels1.len(), 2);

        // Query active delegations by finality provider
        let dels1 = crate::queries::active_delegations_by_fp(deps.as_ref(), "f1".to_string(), true)
            .unwrap()
            .delegations;
        assert_eq!(dels1.len(), 1);
        let err = crate::queries::active_delegations_by_fp(deps.as_ref(), "f2".to_string(), false)
            .unwrap_err();
        assert!(matches!(err, ContractError::Std(NotFound { .. })));
    }

    #[test]
    fn test_fp_info() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        let initial_env = crate::finality::tests::mock_env_height(10);

        instantiate(
            deps.as_mut(),
            initial_env.clone(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Add a finality provider
        let new_fp1 = create_new_finality_provider(1);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), initial_env, info.clone(), msg).unwrap();

        // Add a couple delegations
        let mut del1 = crate::contract::tests::get_derived_btc_delegation(1, &[1]);
        let mut del2 = crate::contract::tests::get_derived_btc_delegation(2, &[1]);

        // Adjust staking amounts
        del1.total_sat = 100;
        del2.total_sat = 150;

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env_height(11), info.clone(), msg).unwrap();

        // Query finality provider info
        let fp =
            crate::queries::finality_provider_info(deps.as_ref(), "f1".to_string(), None).unwrap();
        assert_eq!(
            fp,
            FinalityProviderInfo {
                btc_pk_hex: "f1".to_string(),
                power: 250,
            }
        );

        // Query finality provider info with same height as execute call
        let fp = crate::queries::finality_provider_info(deps.as_ref(), "f1".to_string(), Some(11))
            .unwrap();
        assert_eq!(
            fp,
            FinalityProviderInfo {
                btc_pk_hex: "f1".to_string(),
                power: 0, // Historical data is not checkpoint yet
            }
        );

        // Query finality provider info with past height as execute call
        let fp = crate::queries::finality_provider_info(deps.as_ref(), "f1".to_string(), Some(12))
            .unwrap();
        assert_eq!(
            fp,
            FinalityProviderInfo {
                btc_pk_hex: "f1".to_string(),
                power: 250,
            }
        );

        // Query finality provider info with some larger height
        let fp =
            crate::queries::finality_provider_info(deps.as_ref(), "f1".to_string(), Some(1000))
                .unwrap();
        assert_eq!(
            fp,
            FinalityProviderInfo {
                btc_pk_hex: "f1".to_string(),
                power: 250,
            }
        );
    }

    #[test]
    fn test_fp_info_raw_query() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Add a finality provider
        let new_fp1 = create_new_finality_provider(1);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a delegation
        let mut del1 = crate::contract::tests::get_derived_btc_delegation(1, &[1]);
        // Adjust staking amount
        del1.total_sat = 100;

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Build raw key
        let prefixed_key = namespace_with_key(&[FP_STATE_KEY.as_bytes()], b"f1");
        // Read directly from storage
        let fp_state_raw = deps.storage.get(&prefixed_key).unwrap();
        // Deserialize result
        let fp_state: FinalityProviderState = from_json(fp_state_raw).unwrap();

        assert_eq!(fp_state, FinalityProviderState { power: 100 });
    }

    #[test]
    fn test_fps_by_power() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Add a couple finality providers
        let new_fp1 = create_new_finality_provider(1);
        let new_fp2 = create_new_finality_provider(2);
        let new_fp3 = create_new_finality_provider(3);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone(), new_fp2.clone(), new_fp3.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add some delegations
        let mut del1 = crate::contract::tests::get_derived_btc_delegation(1, &[1, 3]);
        let mut del2 = crate::contract::tests::get_derived_btc_delegation(2, &[2]);
        let mut del3 = crate::contract::tests::get_derived_btc_delegation(3, &[2]);

        // Adjust staking amounts
        del1.total_sat = 100;
        del2.total_sat = 150;
        del3.total_sat = 75;

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone(), del3],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query finality providers by power
        let fps = crate::queries::finality_providers_by_power(deps.as_ref(), None, None)
            .unwrap()
            .fps;
        assert_eq!(fps.len(), 3);
        assert_eq!(fps[0], {
            FinalityProviderInfo {
                btc_pk_hex: "f2".to_string(),
                power: 225,
            }
        });
        assert_eq!(fps[1], {
            FinalityProviderInfo {
                btc_pk_hex: "f3".to_string(),
                power: 100,
            }
        });
        assert_eq!(fps[2], {
            FinalityProviderInfo {
                btc_pk_hex: "f1".to_string(),
                power: 100,
            }
        });

        // Query finality providers power with limit
        let fps = crate::queries::finality_providers_by_power(deps.as_ref(), None, Some(2))
            .unwrap()
            .fps;
        assert_eq!(fps.len(), 2);
        assert_eq!(fps[0], {
            FinalityProviderInfo {
                btc_pk_hex: "f2".to_string(),
                power: 225,
            }
        });
        assert_eq!(fps[1], {
            FinalityProviderInfo {
                btc_pk_hex: "f3".to_string(),
                power: 100,
            }
        });

        // Query finality providers power with start_after
        let fps =
            crate::queries::finality_providers_by_power(deps.as_ref(), Some(fps[1].clone()), None)
                .unwrap()
                .fps;
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0], {
            FinalityProviderInfo {
                btc_pk_hex: "f1".to_string(),
                power: 100,
            }
        });
    }
}
