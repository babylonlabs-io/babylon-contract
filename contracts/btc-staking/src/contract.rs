use crate::error::ContractError;
use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, FinalityProvider, FinalityProviderDescription, ProofOfPossession,
    SlashedBtcDelegation, UnbondedBtcDelegation,
};
use babylon_bindings::BabylonMsg;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::{consensus::deserialize, Transaction};
use cosmwasm_std::{
    ensure_eq, entry_point, to_json_binary, Deps, DepsMut, Empty, Env, MessageInfo, QueryResponse,
    Reply, Response, StdResult, Storage,
};
use cw2::set_contract_version;
use cw_utils::nonpayable;
use hex::ToHex;

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries;
use crate::state::{Config, CONFIG, DELEGATIONS, FPS, FP_DELEGATIONS};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The caller of the instantiation will be the Babylon contract
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    nonpayable(&info)?;
    let denom = deps.querier.query_bonded_denom()?;
    let config = Config {
        denom,
        babylon: info.sender,
    };
    CONFIG.save(deps.storage, &config)?;
    // initialize storage, so no issue when reading for the first time

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_deps: DepsMut, _env: Env, _reply: Reply) -> StdResult<Response> {
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<QueryResponse, ContractError> {
    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&queries::config(deps)?)?),
        QueryMsg::FinalityProvider { btc_pk_hex } => Ok(to_json_binary(
            &queries::finality_provider(deps, btc_pk_hex)?,
        )?),
        QueryMsg::FinalityProviders { start_after, limit } => Ok(to_json_binary(
            &queries::finality_providers(deps, start_after, limit)?,
        )?),
        QueryMsg::Delegation {
            staking_tx_hash_hex,
        } => Ok(to_json_binary(&queries::delegation(
            deps,
            staking_tx_hash_hex,
        )?)?),
        QueryMsg::Delegations { start_after, limit } => Ok(to_json_binary(&queries::delegations(
            deps,
            start_after,
            limit,
        )?)?),
        QueryMsg::DelegationsByFP { btc_pk_hex } => Ok(to_json_binary(
            &queries::delegations_by_fp(deps, btc_pk_hex)?,
        )?),
    }
}

/// This is a no-op just to test how this integrates with wasmd
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: Empty) -> StdResult<Response> {
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    match msg {
        ExecuteMsg::BtcStaking {
            new_fp,
            active_del,
            slashed_del,
            unbonded_del,
        } => handle_btc_staking(
            deps.storage,
            &info,
            &new_fp,
            &active_del,
            &slashed_del,
            &unbonded_del,
        ),
    }
}

/// handle_btc_staking handles the BTC staking operations.
///
pub fn handle_btc_staking(
    storage: &mut dyn Storage,
    info: &MessageInfo,
    new_fps: &[FinalityProvider],
    active_delegations: &[ActiveBtcDelegation],
    _slashed_delegations: &[SlashedBtcDelegation],
    _unbonded_delegations: &[UnbondedBtcDelegation],
) -> Result<Response<BabylonMsg>, ContractError> {
    let config = CONFIG.load(storage)?;
    ensure_eq!(info.sender, config.babylon, ContractError::Unauthorized);

    for fp in new_fps {
        handle_new_fp(storage, fp)?;
    }

    // Process active delegations
    for del in active_delegations {
        handle_active_delegation(storage, del)?;
    }

    // TODO: Process FPs slashing

    // TODO?: Process slashed delegations (needs routing from `babylon-contract`)

    // TODO: Process undelegations

    // TODO: Add events

    Ok(Response::new())
}

/// handle_bew_fp handles registering a new finality provider
pub fn handle_new_fp(
    storage: &mut dyn Storage,
    fp: &FinalityProvider,
) -> Result<(), ContractError> {
    // Avoid overwriting existing finality providers
    if FPS.has(storage, &fp.btc_pk_hex) {
        return Err(ContractError::FinalityProviderAlreadyExists(
            fp.btc_pk_hex.clone(),
        ));
    }
    // validate the finality provider data
    validate_fp(fp)?;

    FPS.save(storage, &fp.btc_pk_hex, fp)?;
    Ok(())
}

fn validate_fp(fp: &FinalityProvider) -> Result<(), ContractError> {
    fp.description
        .as_ref()
        .map(FinalityProviderDescription::validate)
        .transpose()?;

    if fp.btc_pk_hex.is_empty() {
        return Err(ContractError::EmptyBtcPk);
    }

    let _btc_pk = hex::decode(&fp.btc_pk_hex)?;

    // TODO: Validate BTC public key (requires valid BTC PK data)
    // PublicKey::from_slice(&btc_pk)
    //     .map_err(|_| ContractError::InvalidBtcPk(fp.btc_pk_hex.clone()))?;

    match fp.pop {
        Some(ref pop) => validate_pop(pop)?,
        None => return Err(ContractError::MissingPop),
    }

    // Validate master public randomness
    if fp.master_pub_rand.is_empty() {
        return Err(ContractError::EmptyMasterPubRand);
    }

    Ok(())
}

// TODO: Validate proof of possession
fn validate_pop(_pop: &ProofOfPossession) -> Result<(), ContractError> {
    Ok(())
}

/// handle_active_delegations handles adding a new active delegation.
///
pub fn handle_active_delegation(
    storage: &mut dyn Storage,
    delegation: &ActiveBtcDelegation,
) -> Result<(), ContractError> {
    // Basic stateless checks
    validate_delegation(delegation)?;

    // Get params
    // btc_confirmation_depth
    // checkpoint_finalization_timeout
    // minimum_unbonding_time

    // Check unbonding time (staking time from unbonding tx) is larger than min unbonding time
    // which is larger value from:
    // - MinUnbondingTime
    // - CheckpointFinalizationTimeout

    // At this point, we know that unbonding time in request:
    // - is larger than min unbonding time
    // - is smaller than math.MaxUint16 (due to check in req.ValidateBasic())

    // TODO: Verify proof of possession

    // Parse staking tx
    let staking_tx: Transaction = deserialize(&delegation.staking_tx)
        .map_err(|_| ContractError::InvalidBtcTx(delegation.staking_tx.encode_hex()))?;
    // Check staking time is at most uint16
    match staking_tx.lock_time {
        LockTime::Blocks(b) if b.to_consensus_u32() > u16::MAX as u32 => {
            return Err(ContractError::ErrInvalidLockTime(
                b.to_consensus_u32(),
                u16::MAX as u32,
            ));
        }
        LockTime::Blocks(_) => {}
        LockTime::Seconds(_) => {
            return Err(ContractError::ErrInvalidLockType);
        }
    }

    // Get staking tx hash
    let staking_tx_hash = staking_tx.txid();

    // Check if data provided in request, matches data to which staking tx is committed

    // Check staking tx time-lock has correct values
    // get start_height and end_height of the time-lock

    // Ensure staking tx is k-deep

    // Ensure staking tx time-lock has more than w BTC blocks left

    // Verify staking tx info, i.e. inclusion proof

    // Check slashing tx and its consistency with staking tx

    // Decode slashing address

    // Check slashing tx and staking tx are valid and consistent

    // Verify staker signature against slashing path of the staking tx script

    // All good, construct BTCDelegation and insert BTC delegation
    // NOTE: the BTC delegation does not have voting power yet.
    // It will have voting power only when
    // 1) Its corresponding staking tx is k-deep.
    // 2) It receives a covenant signature.

    /*
        TODO: Early unbonding logic
    */

    // Deserialize provided transactions

    // Check that the unbonding tx input is pointing to staking tx

    // Check that staking tx output index matches unbonding tx output index

    // Build unbonding info

    // Get unbonding output index

    // Check that slashing tx and unbonding tx are valid and consistent

    // Check staker signature against slashing path of the unbonding tx

    // Check unbonding tx fees against staking tx
    // - Fee is greater than 0.
    // - Unbonding output value is at least `MinUnbondingValue` percentage of staking output value.

    // All good, add BTC undelegation

    // Check staking tx is not duplicated
    if DELEGATIONS.has(storage, staking_tx_hash.as_ref()) {
        return Err(ContractError::DelegationAlreadyExists(
            staking_tx_hash.to_string(),
        ));
    }

    // Update delegations by registered finality provider
    let mut registered_fp = false;
    for fp_btc_pk in &delegation.fp_btc_pk_list {
        // Skip if finality provider is not registered, as it can belong to another Consumer, or Babylon
        if !FPS.has(storage, fp_btc_pk) {
            continue;
        }
        // - TODO: Skip slashed FPs
        // - TODO?: Skip FPs whose registered epochs are not finalised

        // Save staking hash by finality provider
        let mut fp_delegations = FP_DELEGATIONS
            .may_load(storage, fp_btc_pk)?
            .unwrap_or(vec![]);
        fp_delegations.push(staking_tx_hash.as_byte_array().to_vec());
        FP_DELEGATIONS.save(storage, fp_btc_pk, &fp_delegations)?;
        registered_fp = true;
    }

    if !registered_fp {
        return Err(ContractError::FinalityProviderNotRegistered);
    }
    // Add this BTC delegation
    DELEGATIONS.save(storage, staking_tx_hash.as_ref(), delegation)?;
    // TODO: Emit corresponding events

    Ok(())
}

fn validate_delegation(del: &ActiveBtcDelegation) -> Result<(), ContractError> {
    if del.btc_pk_hex.is_empty() {
        return Err(ContractError::EmptyBtcPk);
    }
    if del.staking_tx.is_empty() {
        return Err(ContractError::EmptyStakingTx);
    }
    if del.slashing_tx.is_empty() {
        return Err(ContractError::EmptySlashingTx);
    }
    let _: Transaction = deserialize(&del.slashing_tx)
        .map_err(|_| ContractError::InvalidBtcTx(hex::encode(&del.slashing_tx)))?;

    // TODO: Verify delegator slashing Schnorr signature

    // Ensure the list of finality provider BTC PKs is not empty
    if del.fp_btc_pk_list.is_empty() {
        return Err(ContractError::EmptyBtcPkList);
    }
    // Ensure the list of finality provider BTC PKs is not duplicated
    check_duplicated_fps(del)?;

    // TODO: Verifications about undelegation info / on-demand unbonding
    // Check unbonding time is lower than max uint16
    if del.unbonding_time > u16::MAX as u32 {
        return Err(ContractError::ErrInvalidUnbondingTime(
            del.unbonding_time,
            u16::MAX as u32,
        ));
    }

    Ok(())
}

fn check_duplicated_fps(del: &ActiveBtcDelegation) -> Result<(), ContractError> {
    let mut fp_btc_pk_set = std::collections::HashSet::new();
    for fp_btc_pk in &del.fp_btc_pk_list {
        if !fp_btc_pk_set.insert(fp_btc_pk) {
            return Err(ContractError::DuplicatedBtcPk(fp_btc_pk.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::contract::ExecuteMsg;
    use babylon_apis::btc_staking_api::{
        CovenantAdaptorSignatures, FinalityProviderDescription, ProofOfPossession,
    };
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Decimal,
    };
    use hex::ToHex;
    use test_utils::get_btc_delegation_and_params;

    const CREATOR: &str = "creator";

    /// Build an active BTC delegation from a BTC delegation
    pub(crate) fn get_active_btc_delegation() -> ActiveBtcDelegation {
        let (del, _) = get_btc_delegation_and_params();

        ActiveBtcDelegation {
            btc_pk_hex: del.btc_pk.encode_hex(),
            fp_btc_pk_list: del
                .fp_btc_pk_list
                .iter()
                .map(|fp_btc_pk| fp_btc_pk.encode_hex())
                .collect(),
            start_height: del.start_height,
            end_height: del.end_height,
            total_sat: del.total_sat,
            staking_tx: del.staking_tx.to_vec(),
            slashing_tx: del.slashing_tx.to_vec(),
            delegator_slashing_sig: vec![],
            covenant_sigs: del
                .covenant_sigs
                .iter()
                .map(|cov_sig| CovenantAdaptorSignatures {
                    cov_pk: cov_sig.cov_pk.to_vec(),
                    adaptor_sigs: cov_sig
                        .adaptor_sigs
                        .iter()
                        .map(|adaptor_sig| adaptor_sig.to_vec())
                        .collect(),
                })
                .collect(),
            staking_output_idx: del.staking_output_idx,
            unbonding_time: del.unbonding_time,
            undelegation_info: None,
            params_version: del.params_version,
        }
    }

    #[test]
    fn instantiate_works() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {};
        let info = mock_info(CREATOR, &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn test_btc_staking_add_fp() {
        let mut deps = mock_dependencies();
        let info = mock_info(CREATOR, &[]);

        instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();

        let new_fp = FinalityProvider {
            description: Some(FinalityProviderDescription {
                moniker: "fp1".to_string(),
                identity: "Finality Provider 1".to_string(),
                website: "https:://fp1.com".to_string(),
                security_contact: "security_contact".to_string(),
                details: "details".to_string(),
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

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        // Only the creator (Babylon contract) can call this
        let other_info = mock_info("other", &[]);
        let err = execute(deps.as_mut(), mock_env(), other_info, msg.clone()).unwrap_err();
        assert_eq!(err, ContractError::Unauthorized);

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        assert_eq!(0, res.messages.len());

        // Check the finality provider has been stored
        let query_res =
            queries::finality_provider(deps.as_ref(), new_fp.btc_pk_hex.clone()).unwrap();
        assert_eq!(query_res, new_fp);

        // Trying to add the same fp again fails
        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert_eq!(
            err,
            ContractError::FinalityProviderAlreadyExists(new_fp.btc_pk_hex.clone())
        );
    }

    #[test]
    fn btc_staking_active_delegation_happy_path() {
        let mut deps = mock_dependencies();
        let info = mock_info(CREATOR, &[]);

        instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();

        // Build valid active delegation
        let active_delegation = get_active_btc_delegation();

        // Register one FP first
        let new_fp = FinalityProvider {
            description: Some(FinalityProviderDescription {
                moniker: "fp1".to_string(),
                identity: "Finality Provider 1".to_string(),
                website: "https:://fp1.com".to_string(),
                security_contact: "security_contact".to_string(),
                details: "details".to_string(),
            }),
            commission: Decimal::percent(5),
            babylon_pk: None,
            btc_pk_hex: active_delegation.fp_btc_pk_list[0].clone(),
            pop: Some(ProofOfPossession {
                btc_sig_type: 0,
                babylon_sig: vec![],
                btc_sig: vec![],
            }),
            master_pub_rand: "master-pub-rand".to_string(),
            registered_epoch: 1,
            slashed_babylon_height: 0,
            slashed_btc_height: 0,
            chain_id: "babylon-euphrates-0.2".to_string(),
        };

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Now add the active delegation
        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![active_delegation.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Check the active delegation is being stored
        let staking_tx: Transaction = deserialize(&active_delegation.staking_tx).unwrap();
        let staking_tx_hash = staking_tx.txid();
        let query_res = queries::delegation(deps.as_ref(), staking_tx_hash.to_string()).unwrap();
        assert_eq!(query_res, active_delegation);
    }
}
