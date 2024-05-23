use crate::error::ContractError;
use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, FinalityProvider, SlashedBtcDelegation, SudoMsg, UnbondedBtcDelegation,
};
use babylon_apis::Validate;
use babylon_bindings::BabylonMsg;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::{consensus::deserialize, Transaction, Txid};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    ensure_eq, to_json_binary, Addr, Binary, CustomQuery, Deps, DepsMut, Empty, Env, MessageInfo,
    QueryRequest, QueryResponse, Reply, Response, StdResult, Storage, WasmQuery,
};
use cw2::set_contract_version;
use cw_utils::nonpayable;
use hex::ToHex;
use prost::bytes::Bytes;
use prost::Message;
use std::str::FromStr;

use babylon_contract::state::btc_light_client::BTC_TIP_KEY;

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries;
use crate::state::{
    fps, Config, BTC_HEIGHT, CONFIG, DELEGATIONS, DELEGATION_FPS, FPS, FP_DELEGATIONS, PARAMS,
};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The caller of the instantiation will be the Babylon contract
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    nonpayable(&info)?;
    let denom = deps.querier.query_bonded_denom()?;
    let config = Config {
        denom,
        babylon: info.sender,
    };
    CONFIG.save(deps.storage, &config)?;
    let params = msg.params.unwrap_or_default();
    PARAMS.save(deps.storage, &params)?;
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
        QueryMsg::Params {} => Ok(to_json_binary(&queries::params(deps)?)?),
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
        QueryMsg::Delegations {
            start_after,
            limit,
            active,
        } => Ok(to_json_binary(&queries::delegations(
            deps,
            start_after,
            limit,
            active,
        )?)?),
        QueryMsg::DelegationsByFP { btc_pk_hex } => Ok(to_json_binary(
            &queries::delegations_by_fp(deps, btc_pk_hex)?,
        )?),
        QueryMsg::FinalityProviderInfo { btc_pk_hex } => Ok(to_json_binary(
            &queries::finality_provider_info(deps, btc_pk_hex)?,
        )?),
        QueryMsg::FinalityProvidersByPower { start_after, limit } => Ok(to_json_binary(
            &queries::finality_providers_by_power(deps, start_after, limit)?,
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
    unbonded_delegations: &[UnbondedBtcDelegation],
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

    // Process undelegations
    for undel in unbonded_delegations {
        handle_undelegation(storage, undel)?;
    }

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
    fp.validate()?;

    FPS.save(storage, &fp.btc_pk_hex, fp)?;
    Ok(())
}

/// handle_active_delegations handles adding a new active delegation.
///
pub fn handle_active_delegation(
    storage: &mut dyn Storage,
    delegation: &ActiveBtcDelegation,
) -> Result<(), ContractError> {
    // Basic stateless checks
    delegation.validate()?;

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

    // All good, check initial BTC undelegation information is present
    // TODO: Check that the sent undelegation info is valid
    match delegation.undelegation_info {
        Some(ref undelegation_info) => {
            // Check that the unbonding tx is there
            if undelegation_info.unbonding_tx.is_empty() {
                return Err(ContractError::EmptyUnbondingTx);
            }

            // Check that the unbonding slashing tx is there
            if undelegation_info.slashing_tx.is_empty() {
                return Err(ContractError::EmptySlashingTx);
            }

            // Check that the delegator slashing signature is there
            if undelegation_info.delegator_slashing_sig.is_empty() {
                return Err(ContractError::EmptySignature);
            }
        }
        None => {
            return Err(ContractError::MissingUnbondingInfo);
        }
    }

    // Check staking tx is not duplicated
    if DELEGATIONS.has(storage, staking_tx_hash.as_ref()) {
        return Err(ContractError::DelegationAlreadyExists(
            staking_tx_hash.to_string(),
        ));
    }

    // Update delegations by registered finality provider
    let fps = fps();
    let mut registered_fp = false;
    for fp_btc_pk in &delegation.fp_btc_pk_list {
        // Skip if finality provider is not registered, as it can belong to another Consumer, or Babylon
        if !FPS.has(storage, fp_btc_pk) {
            continue;
        }
        // - TODO: Skip slashed FPs
        // - TODO?: Skip FPs whose registered epochs are not finalised

        // Update staking tx hash by finality provider map
        let mut fp_delegations = FP_DELEGATIONS
            .may_load(storage, fp_btc_pk)?
            .unwrap_or(vec![]);
        fp_delegations.push(staking_tx_hash.as_byte_array().to_vec());
        FP_DELEGATIONS.save(storage, fp_btc_pk, &fp_delegations)?;

        // Update finality provider by staking tx hash reverse map
        let mut delegation_fps = DELEGATION_FPS
            .may_load(storage, staking_tx_hash.as_ref())?
            .unwrap_or(vec![]);
        delegation_fps.push(fp_btc_pk.clone());
        DELEGATION_FPS.save(storage, staking_tx_hash.as_ref(), &delegation_fps)?;

        // Update aggregated voting power by FP
        fps.update(storage, fp_btc_pk, |fpi| {
            let mut fpi = fpi.unwrap_or_default();
            fpi.power += delegation.total_sat;
            Ok::<_, ContractError>(fpi)
        })?;

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

/// handle_undelegation handles undelegation from an active delegation.
///
fn handle_undelegation(
    storage: &mut dyn Storage,
    undelegation: &UnbondedBtcDelegation,
) -> Result<(), ContractError> {
    // Basic stateless checks
    undelegation.validate()?;

    let staking_tx_hash = Txid::from_str(&undelegation.staking_tx_hash)?;
    let mut btc_del = DELEGATIONS.load(storage, staking_tx_hash.as_ref())?;

    // TODO: Ensure the BTC delegation is active

    if undelegation.unbonding_tx_sig.is_empty() {
        return Err(ContractError::EmptySignature);
    }
    // TODO: Verify the signature on the unbonding tx is from the delegator

    // Add the signature to the BTC delegation's undelegation and set back
    btc_undelegate(
        storage,
        &staking_tx_hash,
        &mut btc_del,
        &undelegation.unbonding_tx_sig,
    )?;

    // Discount the voting power from the affected finality providers
    let affected_fps = DELEGATION_FPS.load(storage, staking_tx_hash.as_ref())?;
    let fps = fps();
    for fp in affected_fps {
        fps.update(storage, &fp, |fpi| {
            let mut fpi = fpi.ok_or(ContractError::FinalityProviderNotFound(fp.clone()))?; // should never happen
            fpi.power -= btc_del.total_sat;
            Ok::<_, ContractError>(fpi)
        })?;
    }

    Ok(())
}

/// btc_undelegate adds the signature of the unbonding tx signed by the staker to the given BTC
/// delegation
fn btc_undelegate(
    storage: &mut dyn Storage,
    staking_tx_hash: &Txid,
    btc_del: &mut ActiveBtcDelegation,
    unbondind_tx_sig: &[u8],
) -> Result<(), ContractError> {
    match &mut btc_del.undelegation_info {
        Some(undelegation_info) => {
            undelegation_info.delegator_unbonding_sig = unbondind_tx_sig.to_vec();
        }
        None => {
            return Err(ContractError::MissingUnbondingInfo);
        }
    }

    // Set BTC delegation back to KV store
    DELEGATIONS.save(storage, staking_tx_hash.as_ref(), btc_del)?;

    // TODO? Notify subscriber about this unbonded BTC delegation
    //  - Who are subscribers in this context?
    //  - How to notify them? Emit event?

    // TODO? Record event that the BTC delegation becomes unbonded at this height

    Ok(())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(
    mut deps: DepsMut,
    env: Env,
    msg: SudoMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    match msg {
        SudoMsg::BeginBlock {} => handle_begin_block(&mut deps, env),
    }
}

fn handle_begin_block(deps: &mut DepsMut, env: Env) -> Result<Response<BabylonMsg>, ContractError> {
    // Index BTC height at the current height
    index_btc_height(deps, env.block.height)?;

    // Update voting power distribution
    // update_power_distribution();

    Ok(Response::new())
}

// index_btc_height indexes the current BTC height, and saves it to the state
fn index_btc_height(deps: &mut DepsMut, height: u64) -> Result<(), ContractError> {
    let btc_tip = get_btc_tip(deps)?;

    Ok(BTC_HEIGHT.save(deps.storage, height, &btc_tip.height)?)
}

/// TODO: Move this helper to apis package
fn encode_raw_query<T: Into<Binary>, Q: CustomQuery>(addr: &Addr, key: T) -> QueryRequest<Q> {
    WasmQuery::Raw {
        contract_addr: addr.into(),
        key: key.into(),
    }
    .into()
}

/// get_btc_tip queries the Babylon contract for the latest BTC tip
fn get_btc_tip(deps: &DepsMut) -> Result<BtcHeaderInfo, ContractError> {
    // Get the BTC tip from the babylon contract through a raw query
    let babylon_addr = CONFIG.load(deps.storage)?.babylon;
    let query = encode_raw_query(&babylon_addr, BTC_TIP_KEY.as_bytes());

    let tip_bytes: Bytes = deps.querier.query(&query)?;
    Ok(BtcHeaderInfo::decode(tip_bytes)?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::contract::ExecuteMsg;
    use babylon_apis::btc_staking_api::{
        BtcUndelegationInfo, CovenantAdaptorSignatures, FinalityProviderDescription,
        ProofOfPossession,
    };
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Decimal, StdError,
    };
    use hex::ToHex;
    use test_utils::get_btc_delegation_and_params;

    const CREATOR: &str = "creator";

    /// Build an active BTC delegation from a BTC delegation
    pub(crate) fn get_active_btc_delegation() -> ActiveBtcDelegation {
        let (del, _) = get_btc_delegation_and_params();
        let btc_undelegation = del.btc_undelegation.unwrap();

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
            undelegation_info: Some(BtcUndelegationInfo {
                unbonding_tx: btc_undelegation.unbonding_tx.to_vec(),
                slashing_tx: btc_undelegation.slashing_tx.to_vec(),
                delegator_unbonding_sig: vec![],
                delegator_slashing_sig: btc_undelegation.delegator_slashing_sig.to_vec(),
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            }),
            params_version: del.params_version,
        }
    }

    #[test]
    fn instantiate_works() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg { params: None };
        let info = mock_info(CREATOR, &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn test_btc_staking_add_fp() {
        let mut deps = mock_dependencies();
        let info = mock_info(CREATOR, &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg { params: None },
        )
        .unwrap();

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

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg { params: None },
        )
        .unwrap();

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

        // Check that the finality provider power is not there yet
        let err =
            queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone()).unwrap_err();
        assert!(matches!(err, StdError::NotFound { .. }));

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

        // Check that the finality provider power has been updated
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone()).unwrap();
        assert_eq!(fp.power, active_delegation.total_sat);
    }

    #[test]
    fn btc_staking_undelegation_works() {
        let mut deps = mock_dependencies();
        let info = mock_info(CREATOR, &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg { params: None },
        )
        .unwrap();

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
            active_del: vec![active_delegation.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Check the delegation is active (it has no unbonding or slashing tx signature)
        let active_delegation_undelegation = active_delegation.undelegation_info.clone().unwrap();
        // Compute the staking tx hash
        let staking_tx: Transaction = deserialize(&active_delegation.staking_tx).unwrap();
        let staking_tx_hash_hex = staking_tx.txid().to_string();

        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex.clone()).unwrap();
        let btc_undelegation = btc_del.undelegation_info.unwrap();
        assert_eq!(
            btc_undelegation,
            BtcUndelegationInfo {
                unbonding_tx: active_delegation_undelegation.unbonding_tx,
                slashing_tx: active_delegation_undelegation.slashing_tx,
                delegator_unbonding_sig: vec![],
                delegator_slashing_sig: active_delegation_undelegation.delegator_slashing_sig,
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            }
        );

        // Now send the undelegation message
        let undelegation = UnbondedBtcDelegation {
            staking_tx_hash: staking_tx_hash_hex.clone(),
            unbonding_tx_sig: vec![0x01, 0x02, 0x03], // TODO: Use a proper signature
        };

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![undelegation.clone()],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Check the delegation is not active anymore (updated with the unbonding tx signature)
        let active_delegation_undelegation = active_delegation.undelegation_info.unwrap();
        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex).unwrap();
        let btc_undelegation = btc_del.undelegation_info.unwrap();
        assert_eq!(
            btc_undelegation,
            BtcUndelegationInfo {
                unbonding_tx: active_delegation_undelegation.unbonding_tx,
                slashing_tx: active_delegation_undelegation.slashing_tx,
                delegator_unbonding_sig: vec![0x01, 0x02, 0x03],
                delegator_slashing_sig: active_delegation_undelegation.delegator_slashing_sig,
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            }
        );

        // Check the finality provider power has been updated
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone()).unwrap();
        assert_eq!(fp.power, 0);
    }
}
