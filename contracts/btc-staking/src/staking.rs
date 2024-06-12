use hex::ToHex;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid};

use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, Storage};

use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, FinalityProvider, NewFinalityProvider, SlashedBtcDelegation,
    UnbondedBtcDelegation,
};
use babylon_apis::Validate;
use babylon_bindings::BabylonMsg;

use crate::error::ContractError;
use crate::state::config::{ADMIN, CONFIG};
use crate::state::staking::{fps, DELEGATIONS, DELEGATION_FPS, FPS, FP_DELEGATIONS};

/// handle_btc_staking handles the BTC staking operations
pub fn handle_btc_staking(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    new_fps: &[NewFinalityProvider],
    active_delegations: &[ActiveBtcDelegation],
    _slashed_delegations: &[SlashedBtcDelegation],
    unbonded_delegations: &[UnbondedBtcDelegation],
) -> Result<Response<BabylonMsg>, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.babylon && !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized);
    }

    for fp in new_fps {
        handle_new_fp(deps.storage, fp)?;
    }

    // Process active delegations
    for del in active_delegations {
        handle_active_delegation(deps.storage, env.block.height, del)?;
    }

    // TODO: Process FPs slashing

    // TODO?: Process slashed delegations (needs routing from `babylon-contract`)

    // Process undelegations
    for undel in unbonded_delegations {
        handle_undelegation(deps.storage, env.block.height, undel)?;
    }

    // TODO: Add events

    Ok(Response::new())
}

/// handle_bew_fp handles registering a new finality provider
pub fn handle_new_fp(
    storage: &mut dyn Storage,
    new_fp: &NewFinalityProvider,
) -> Result<(), ContractError> {
    // Avoid overwriting existing finality providers
    if FPS.has(storage, &new_fp.btc_pk_hex) {
        return Err(ContractError::FinalityProviderAlreadyExists(
            new_fp.btc_pk_hex.clone(),
        ));
    }
    // validate the finality provider data
    new_fp.validate()?;
    // get DB object
    let fp = FinalityProvider::from(new_fp);
    // save to DB
    FPS.save(storage, &fp.btc_pk_hex, &fp)?;
    Ok(())
}

/// handle_active_delegations handles adding a new active delegation.
///
pub fn handle_active_delegation(
    storage: &mut dyn Storage,
    height: u64,
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
        fps.update(storage, fp_btc_pk, height, |fp_state| {
            let mut fp_state = fp_state.unwrap_or_default();
            fp_state.power = fp_state.power.saturating_add(delegation.total_sat);
            Ok::<_, ContractError>(fp_state)
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
    height: u64,
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
        fps.update(storage, &fp, height, |fp_state| {
            let mut fp_state =
                fp_state.ok_or(ContractError::FinalityProviderNotFound(fp.clone()))?; // should never happen
            fp_state.power = fp_state.power.saturating_sub(btc_del.total_sat);
            Ok::<_, ContractError>(fp_state)
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
            undelegation_info.delegator_unbonding_sig = unbondind_tx_sig.to_vec().into();
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

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::Binary;

    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};

    use babylon_apis::btc_staking_api::BtcUndelegationInfo;

    use crate::contract::tests::{
        create_new_finality_provider, get_active_btc_delegation, CREATOR, INIT_ADMIN,
    };
    use crate::contract::{execute, instantiate};
    use crate::msg::{ExecuteMsg, InstantiateMsg};
    use crate::queries;

    #[test]
    fn test_btc_staking_add_fp_unauthorized() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: Some(init_admin.to_string()), // Admin provided
            },
        )
        .unwrap();

        let new_fp = create_new_finality_provider();

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        // Only the Creator or Admin can call this
        let other_info = message_info(&deps.api.addr_make("other"), &[]);
        let err = execute(deps.as_mut(), mock_env(), other_info, msg.clone()).unwrap_err();
        assert_eq!(err, ContractError::Unauthorized);
    }

    #[test]
    fn test_btc_staking_add_fp_admin() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: Some(init_admin.to_string()), // Admin provided
            },
        )
        .unwrap();

        let admin_info = message_info(&init_admin, &[]); // Mock info for the admin
        let new_fp = create_new_finality_provider();

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        // Use admin_info to execute the message
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), msg.clone()).unwrap();
        assert_eq!(0, res.messages.len());

        // Check the finality provider has been stored
        let query_res =
            queries::finality_provider(deps.as_ref(), new_fp.btc_pk_hex.clone()).unwrap();
        // get DB object
        let fp = FinalityProvider::from(&new_fp);
        assert_eq!(query_res, fp);

        // Trying to add the same fp again fails
        let err = execute(deps.as_mut(), mock_env(), admin_info, msg).unwrap_err();
        assert_eq!(
            err,
            ContractError::FinalityProviderAlreadyExists(new_fp.btc_pk_hex.clone())
        );
    }

    #[test]
    fn btc_staking_active_delegation_happy_path() {
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

        // Build valid active delegation
        let active_delegation = get_active_btc_delegation();

        // Register one FP first
        let mut new_fp = create_new_finality_provider();
        new_fp
            .btc_pk_hex
            .clone_from(&active_delegation.fp_btc_pk_list[0]);

        // Check that the finality provider has no power yet
        let res = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(res.power, 0);

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
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(fp.power, active_delegation.total_sat);
    }

    #[test]
    fn btc_staking_undelegation_works() {
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

        // Build valid active delegation
        let active_delegation = get_active_btc_delegation();

        // Register one FP first
        let mut new_fp = create_new_finality_provider();
        new_fp
            .btc_pk_hex
            .clone_from(&active_delegation.fp_btc_pk_list[0]);

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
                delegator_unbonding_sig: Binary::new(vec![]),
                delegator_slashing_sig: active_delegation_undelegation.delegator_slashing_sig,
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            }
        );

        // Now send the undelegation message
        let undelegation = UnbondedBtcDelegation {
            staking_tx_hash: staking_tx_hash_hex.clone(),
            unbonding_tx_sig: Binary::new(vec![0x01, 0x02, 0x03]), // TODO: Use a proper signature
        };

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![undelegation.clone()],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Check the delegation is not active any more (updated with the unbonding tx signature)
        let active_delegation_undelegation = active_delegation.undelegation_info.unwrap();
        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex).unwrap();
        let btc_undelegation = btc_del.undelegation_info.unwrap();
        assert_eq!(
            btc_undelegation,
            BtcUndelegationInfo {
                unbonding_tx: active_delegation_undelegation.unbonding_tx,
                slashing_tx: active_delegation_undelegation.slashing_tx,
                delegator_unbonding_sig: Binary::new(vec![0x01, 0x02, 0x03]),
                delegator_slashing_sig: active_delegation_undelegation.delegator_slashing_sig,
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            }
        );

        // Check the finality provider power has been updated
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(fp.power, 0);
    }
}
