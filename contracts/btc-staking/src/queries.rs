use crate::error::ContractError;
use crate::error::ContractError::WrongHashLength;
use crate::msg::{BtcDelegationsResponse, DelegationsByFPResponse, FinalityProvidersResponse};
use crate::state::{Config, CONFIG, DELEGATIONS, FPS, FP_DELEGATIONS, HASH_SIZE};
use babylon_apis::btc_staking_api::{ActiveBtcDelegation, FinalityProvider};
use cosmwasm_std::{Deps, Order, StdResult};
use cw_storage_plus::Bound;

pub fn config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
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

pub fn delegation(
    deps: Deps,
    staking_tx_hash_hex: String,
) -> Result<ActiveBtcDelegation, ContractError> {
    let staking_tx_hash = hex::decode(staking_tx_hash_hex)?;
    let staking_tx_hash: [u8; HASH_SIZE] = staking_tx_hash
        .clone()
        .try_into()
        .map_err(|_| WrongHashLength(staking_tx_hash.len()))?;
    Ok(DELEGATIONS.load(deps.storage, &staking_tx_hash)?)
}

pub fn delegations(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> Result<BtcDelegationsResponse, ContractError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after.as_ref().map(hex::decode).transpose()?;
    let start_after: Option<[u8; HASH_SIZE]> = start_after
        .clone()
        .map(|s| s.try_into())
        .transpose()
        .map_err(|_| WrongHashLength(start_after.unwrap().len()))?;
    let start_after = start_after.as_ref().map(Bound::exclusive);
    let delegations = DELEGATIONS
        .range_raw(deps.storage, start_after, None, Order::Ascending)
        .take(limit)
        .map(|item| item.map(|(_, v)| v))
        .collect::<Result<Vec<ActiveBtcDelegation>, _>>()?;
    Ok(BtcDelegationsResponse { delegations })
}

pub fn delegations_by_fp(
    deps: Deps,
    btc_pk_hex: String,
) -> Result<DelegationsByFPResponse, ContractError> {
    let tx_hashes = FP_DELEGATIONS.load(deps.storage, &btc_pk_hex)?;
    let tx_hashes = tx_hashes.iter().map(hex::encode).collect::<Vec<String>>();
    Ok(DelegationsByFPResponse { hashes: tx_hashes })
}

#[cfg(test)]
mod tests {
    use crate::contract::{execute, instantiate};
    use crate::error::ContractError;
    use babylon_apis::btc_staking_api::{
        ActiveBtcDelegation, FinalityProvider, FinalityProviderDescription, ProofOfPossession,
    };
    use bitcoin::Transaction;
    use cosmwasm_std::testing::mock_info;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::Decimal;
    use cosmwasm_std::StdError::NotFound;
    use hex::ToHex;

    use crate::msg::{ExecuteMsg, InstantiateMsg};

    const CREATOR: &str = "creator";

    #[test]
    fn test_finality_providers() {
        let mut deps = mock_dependencies();
        let info = mock_info(CREATOR, &[]);

        instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();

        // Add a couple finality providers
        let fp1 = FinalityProvider {
            description: Some(FinalityProviderDescription {
                moniker: "fp1".to_string(),
                identity: "Finality Provider 1".to_string(),
                website: "https:://fp1.com".to_string(),
                security_contact: "security_contact".to_string(),
                details: "details fp1".to_string(),
            }),
            commission: Decimal::percent(5),
            babylon_pk: None,
            btc_pk_hex: "f1".to_string(),
            pop: Some(ProofOfPossession {
                btc_sig_type: 0,
                babylon_sig: vec![],
                btc_sig: vec![],
            }),
            master_pub_rand: "master-pub-rand".to_string(),
            registered_epoch: 1,
            slashed_babylon_height: 0,
            slashed_btc_height: 0,
            chain_id: "osmosis-1".to_string(),
        };

        let fp2 = FinalityProvider {
            description: Some(FinalityProviderDescription {
                moniker: "fp2".to_string(),
                identity: "Finality Provider 2".to_string(),
                website: "https:://fp2.com".to_string(),
                security_contact: "security_contact".to_string(),
                details: "details fp2".to_string(),
            }),
            commission: Decimal::percent(5),
            babylon_pk: None,
            btc_pk_hex: "f2".to_string(),
            pop: Some(ProofOfPossession {
                btc_sig_type: 0,
                babylon_sig: vec![],
                btc_sig: vec![],
            }),
            master_pub_rand: "master-pub-rand".to_string(),
            registered_epoch: 2,
            slashed_babylon_height: 0,
            slashed_btc_height: 0,
            chain_id: "osmosis-1".to_string(),
        };

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![fp1.clone(), fp2.clone()],
            slashed_fp: vec![],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query finality providers
        let fps = crate::queries::finality_providers(deps.as_ref(), None, None)
            .unwrap()
            .fps;
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
        let info = mock_info(CREATOR, &[]);

        instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();

        // Add a couple finality providers
        let fp1 = FinalityProvider {
            description: Some(FinalityProviderDescription {
                moniker: "fp1".to_string(),
                identity: "Finality Provider 1".to_string(),
                website: "https:://fp1.com".to_string(),
                security_contact: "security_contact".to_string(),
                details: "details fp1".to_string(),
            }),
            commission: Decimal::percent(5),
            babylon_pk: None,
            btc_pk_hex: "f1".to_string(),
            pop: Some(ProofOfPossession {
                btc_sig_type: 0,
                babylon_sig: vec![],
                btc_sig: vec![],
            }),
            master_pub_rand: "master-pub-rand".to_string(),
            registered_epoch: 1,
            slashed_babylon_height: 0,
            slashed_btc_height: 0,
            chain_id: "osmosis-1".to_string(),
        };

        let fp2 = FinalityProvider {
            description: Some(FinalityProviderDescription {
                moniker: "fp2".to_string(),
                identity: "Finality Provider 2".to_string(),
                website: "https:://fp2.com".to_string(),
                security_contact: "security_contact".to_string(),
                details: "details fp2".to_string(),
            }),
            commission: Decimal::percent(5),
            babylon_pk: None,
            btc_pk_hex: "f2".to_string(),
            pop: Some(ProofOfPossession {
                btc_sig_type: 0,
                babylon_sig: vec![],
                btc_sig: vec![],
            }),
            master_pub_rand: "master-pub-rand".to_string(),
            registered_epoch: 2,
            slashed_babylon_height: 0,
            slashed_btc_height: 0,
            chain_id: "osmosis-1".to_string(),
        };

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![fp1.clone(), fp2.clone()],
            slashed_fp: vec![],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a couple delegations
        let base_del = crate::contract::tests::get_active_btc_delegation();

        let del1 = ActiveBtcDelegation {
            btc_pk_hex: "d1".to_string(),
            fp_btc_pk_list: vec!["f1".to_string()],
            start_height: 1,
            end_height: 2,
            total_sat: 100,
            staking_tx: base_del.staking_tx.clone(),
            slashing_tx: base_del.slashing_tx.clone(),
            delegator_slashing_sig: vec![],
            covenant_sigs: vec![],
            staking_output_idx: 0,
            unbonding_time: 1234,
            undelegation_info: None,
            params_version: 1,
        };

        let mut del2 = ActiveBtcDelegation {
            btc_pk_hex: "d2".to_string(),
            fp_btc_pk_list: vec!["f2".to_string()],
            start_height: 2,
            end_height: 3,
            total_sat: 200,
            staking_tx: base_del.staking_tx.clone(),
            slashing_tx: base_del.slashing_tx.clone(),
            delegator_slashing_sig: vec![],
            covenant_sigs: vec![],
            staking_output_idx: 0,
            unbonding_time: 1234,
            undelegation_info: None,
            params_version: 1,
        };
        // Avoid repeated staking tx hash
        del2.staking_tx[0] += 1;
        // Avoid repeated slashing tx hash
        del2.slashing_tx[0] += 1;

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            slashed_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query delegations
        let dels = crate::queries::delegations(deps.as_ref(), None, None)
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 2);
        assert_eq!(dels[0], del1);
        assert_eq!(dels[1], del2);

        // Query delegations with limit
        let dels = crate::queries::delegations(deps.as_ref(), None, Some(1))
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0], del1);

        // Query delegations with start_after
        let staking_tx: Transaction = bitcoin::consensus::deserialize(&del1.staking_tx).unwrap();
        let staking_tx_hash = staking_tx.txid();
        let staking_tx_hash_hex = staking_tx_hash.encode_hex();
        let dels = crate::queries::delegations(deps.as_ref(), Some(staking_tx_hash_hex), None)
            .unwrap()
            .delegations;

        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0], del2);
    }

    #[test]
    fn test_delegations_by_fp() {
        let mut deps = mock_dependencies();
        let info = mock_info(CREATOR, &[]);

        instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();

        // Add a couple finality providers
        let fp1 = FinalityProvider {
            description: Some(FinalityProviderDescription {
                moniker: "fp1".to_string(),
                identity: "Finality Provider 1".to_string(),
                website: "https:://fp1.com".to_string(),
                security_contact: "security_contact".to_string(),
                details: "details fp1".to_string(),
            }),
            commission: Decimal::percent(5),
            babylon_pk: None,
            btc_pk_hex: "f1".to_string(),
            pop: Some(ProofOfPossession {
                btc_sig_type: 0,
                babylon_sig: vec![],
                btc_sig: vec![],
            }),
            master_pub_rand: "master-pub-rand".to_string(),
            registered_epoch: 1,
            slashed_babylon_height: 0,
            slashed_btc_height: 0,
            chain_id: "osmosis-1".to_string(),
        };

        let fp2 = FinalityProvider {
            description: Some(FinalityProviderDescription {
                moniker: "fp2".to_string(),
                identity: "Finality Provider 2".to_string(),
                website: "https:://fp2.com".to_string(),
                security_contact: "security_contact".to_string(),
                details: "details fp2".to_string(),
            }),
            commission: Decimal::percent(5),
            babylon_pk: None,
            btc_pk_hex: "f2".to_string(),
            pop: Some(ProofOfPossession {
                btc_sig_type: 0,
                babylon_sig: vec![],
                btc_sig: vec![],
            }),
            master_pub_rand: "master-pub-rand".to_string(),
            registered_epoch: 2,
            slashed_babylon_height: 0,
            slashed_btc_height: 0,
            chain_id: "osmosis-1".to_string(),
        };

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![fp1.clone(), fp2.clone()],
            slashed_fp: vec![],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a couple delegations
        let base_del = crate::contract::tests::get_active_btc_delegation();

        let del1 = ActiveBtcDelegation {
            btc_pk_hex: "d1".to_string(),
            fp_btc_pk_list: vec!["f1".to_string()],
            start_height: 1,
            end_height: 2,
            total_sat: 100,
            staking_tx: base_del.staking_tx.clone(),
            slashing_tx: base_del.slashing_tx.clone(),
            delegator_slashing_sig: vec![],
            covenant_sigs: vec![],
            staking_output_idx: 0,
            unbonding_time: 1234,
            undelegation_info: None,
            params_version: 1,
        };

        let mut del2 = ActiveBtcDelegation {
            btc_pk_hex: "d2".to_string(),
            fp_btc_pk_list: vec!["f2".to_string()],
            start_height: 2,
            end_height: 3,
            total_sat: 200,
            staking_tx: base_del.staking_tx.clone(),
            slashing_tx: base_del.slashing_tx.clone(),
            delegator_slashing_sig: vec![],
            covenant_sigs: vec![],
            staking_output_idx: 0,
            unbonding_time: 1234,
            undelegation_info: None,
            params_version: 1,
        };
        // Avoid repeated staking tx hash
        del2.staking_tx[0] += 1;
        // Avoid repeated slashing tx hash
        del2.slashing_tx[0] += 1;

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            slashed_fp: vec![],
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
}
