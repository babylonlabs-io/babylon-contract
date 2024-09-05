use hex::ToHex;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid};
use cosmwasm_std::{DepsMut, Env, Event, MessageInfo, Order, Response, Storage};

use crate::error::ContractError;
use crate::msg::FinalityProviderInfo;
use crate::state::config::{Params, ADMIN, CONFIG, PARAMS};
use crate::state::staking::{
    fps, BtcDelegation, FinalityProviderState, ACTIVATED_HEIGHT, DELEGATIONS, DELEGATION_FPS, FPS,
    FP_DELEGATIONS, FP_SET, TOTAL_POWER,
};
use crate::state::BTC_HEIGHT;
use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, FinalityProvider, NewFinalityProvider, SlashedBtcDelegation,
    UnbondedBtcDelegation,
};
use babylon_apis::Validate;
use babylon_bindings::BabylonMsg;

#[cfg(feature = "full-validation")]
use bitcoin::Address;
#[cfg(feature = "full-validation")]
use bitcoin::XOnlyPublicKey;

/// handle_btc_staking handles the BTC staking operations
pub fn handle_btc_staking(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    new_fps: &[NewFinalityProvider],
    active_delegations: &[ActiveBtcDelegation],
    slashed_delegations: &[SlashedBtcDelegation],
    unbonded_delegations: &[UnbondedBtcDelegation],
) -> Result<Response<BabylonMsg>, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.babylon && !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized);
    }

    let mut res = Response::new();

    for fp in new_fps {
        handle_new_fp(deps.storage, fp, env.block.height)?;
        // TODO: Add event
    }

    // Process active delegations
    for del in active_delegations {
        handle_active_delegation(deps.storage, env.block.height, del)?;
        // TODO: Add event
    }

    // Process slashed delegations
    for del in slashed_delegations {
        let ev = handle_slashed_delegation(deps.storage, env.block.height, del)?;
        res = res.add_event(ev);
    }

    // Process undelegations
    for undel in unbonded_delegations {
        let ev = handle_undelegation(deps.storage, env.block.height, undel)?;
        res = res.add_event(ev);
    }

    Ok(res)
}

/// handle_bew_fp handles registering a new finality provider
pub fn handle_new_fp(
    storage: &mut dyn Storage,
    new_fp: &NewFinalityProvider,
    height: u64,
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
    // Set its voting power to zero
    let fp_state = FinalityProviderState::default();
    fps().save(storage, &fp.btc_pk_hex, &fp_state, height)?;

    Ok(())
}

/// verify_active_delegation is a placeholder for the full validation logic
///
/// It is marked with `#[cfg(feature = "full-validation")]` so that it
/// is not included in the build if the `full-validation` feature is disabled.
/// TODO: fix contract size when full-validation is enabled
#[cfg(feature = "full-validation")]
fn verify_active_delegation(
    params: &Params,
    active_delegation: &ActiveBtcDelegation,
    staking_tx: &Transaction,
) -> Result<(), ContractError> {
    // get staker's public key
    let staker_pk = XOnlyPublicKey::from_str(&active_delegation.btc_pk_hex)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
    // get all FP's public keys
    let fp_pks: Vec<XOnlyPublicKey> = active_delegation
        .fp_btc_pk_list
        .iter()
        .map(|pk_hex| {
            XOnlyPublicKey::from_str(pk_hex)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
        })
        .collect::<Result<Vec<XOnlyPublicKey>, ContractError>>()?;
    // get all covenant members' public keys
    let cov_pks: Vec<XOnlyPublicKey> = params
        .covenant_pks
        .iter()
        .map(|pk_hex| {
            XOnlyPublicKey::from_str(pk_hex)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
        })
        .collect::<Result<Vec<XOnlyPublicKey>, ContractError>>()?;

    // Check if data provided in request, matches data to which staking tx is
    // committed

    // TODO: Check staking tx time-lock has correct values
    // get start_height and end_height of the time-lock

    // TODO: Ensure staking tx is k-deep

    // TODO: Ensure staking tx time-lock has more than w BTC blocks left

    // TODO: Verify staking tx info, i.e. inclusion proof

    // Check slashing tx and its consistency with staking tx
    let slashing_tx: Transaction = deserialize(&active_delegation.slashing_tx)
        .map_err(|_| ContractError::InvalidBtcTx(active_delegation.slashing_tx.encode_hex()))?;

    // decode slashing address
    let slashing_address: Address = Address::from_str(&params.slashing_address)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?
        .assume_checked();

    // Check slashing tx and staking tx are valid and consistent
    let slashing_rate = params
        .slashing_rate
        .parse::<f64>()
        .map_err(|_| ContractError::InvalidBtcTx("invalid slashing rate".to_string()))?;
    babylon_btcstaking::tx_verify::check_transactions(
        &slashing_tx,
        &staking_tx,
        active_delegation.staking_output_idx,
        params.min_slashing_tx_fee_sat,
        slashing_rate,
        &slashing_address,
        &staker_pk,
        active_delegation.unbonding_time as u16,
    )?;

    // TODO: Verify proof of possession

    /*
        verify staker signature against slashing path of the staking tx script
    */

    // get the slashing path script
    let staking_output = &staking_tx.output[active_delegation.staking_output_idx as usize];
    let staking_time = (active_delegation.end_height - active_delegation.start_height) as u16;
    let babylon_script_paths = babylon_btcstaking::scripts_utils::BabylonScriptPaths::new(
        &staker_pk,
        &fp_pks,
        &cov_pks,
        params.covenant_quorum as usize,
        staking_time,
    )?;
    let slashing_path_script = babylon_script_paths.slashing_path_script;

    // get the staker's signature on the slashing tx
    let staker_sig =
        k256::schnorr::Signature::try_from(active_delegation.delegator_slashing_sig.as_slice())
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // Verify the signature
    babylon_btcstaking::sig_verify::verify_transaction_sig_with_output(
        &slashing_tx,
        staking_output,
        slashing_path_script.as_script(),
        &staker_pk,
        &staker_sig,
    )
    .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // TODO: verify covenant signatures

    // TODO: Check unbonding time (staking time from unbonding tx) is larger than min unbonding time
    // which is larger value from:
    // - MinUnbondingTime
    // - CheckpointFinalizationTimeout

    // At this point, we know that unbonding time in request:
    // - is larger than min unbonding time
    // - is smaller than math.MaxUint16 (due to check in req.ValidateBasic())

    /*
        TODO: Early unbonding logic
    */

    // TODO: Deserialize provided transactions

    // TODO: Check that the unbonding tx input is pointing to staking tx

    // TODO: Check that staking tx output index matches unbonding tx output index

    // TODO: Build unbonding info

    // TODO: Get unbonding output index

    // TODO: Check that slashing tx and unbonding tx are valid and consistent

    // TODO: Check staker signature against slashing path of the unbonding tx

    // TODO: Check unbonding tx fees against staking tx
    // - Fee is greater than 0.
    // - Unbonding output value is at least `MinUnbondingValue` percentage of staking output value.

    Ok(())
}

/// verify_active_delegation is a placeholder for the full validation logic
///
/// It is marked with `#[cfg(not(feature = "full-validation"))]` so that it
/// is not included in the build if the `full-validation` feature is enabled.
#[cfg(not(feature = "full-validation"))]
fn verify_active_delegation(
    _params: &Params,
    _active_delegation: &ActiveBtcDelegation,
    _staking_tx: &Transaction,
) -> Result<(), ContractError> {
    Ok(())
}

pub fn handle_active_delegation(
    storage: &mut dyn Storage,
    height: u64,
    active_delegation: &ActiveBtcDelegation,
) -> Result<(), ContractError> {
    // TODO: Get params
    // btc_confirmation_depth
    // checkpoint_finalization_timeout
    // minimum_unbonding_time

    let params = PARAMS.load(storage)?;

    // Basic stateless checks
    active_delegation.validate()?;

    // TODO: Ensure all finality providers
    // - are known to Babylon,
    // - at least 1 one of them is a Babylon finality provider,
    // - are not slashed, and
    // - their registered epochs are finalised
    // and then check whether the BTC stake is restaked to FPs of consumers
    // TODO: ensure the BTC delegation does not restake to too many finality providers
    // (pending concrete design)

    // Parse staking tx
    let staking_tx: Transaction = deserialize(&active_delegation.staking_tx)
        .map_err(|_| ContractError::InvalidBtcTx(active_delegation.staking_tx.encode_hex()))?;
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

    // Check staking tx is not duplicated
    if DELEGATIONS.has(storage, staking_tx_hash.as_ref()) {
        return Err(ContractError::DelegationAlreadyExists(
            staking_tx_hash.to_string(),
        ));
    }

    // full validations on the active delegation
    verify_active_delegation(&params, active_delegation, &staking_tx)?;

    // All good, construct BTCDelegation and insert BTC delegation
    // NOTE: the BTC delegation does not have voting power yet.
    // It will have voting power only when
    // 1) Its corresponding staking tx is k-deep.
    // 2) It receives a covenant signature.

    // Update delegations by registered finality provider
    let fps = fps();
    let mut registered_fp = false;
    for fp_btc_pk_hex in &active_delegation.fp_btc_pk_list {
        // Skip if finality provider is not registered, as it can belong to another Consumer, or Babylon
        if !FPS.has(storage, fp_btc_pk_hex) {
            continue;
        }

        // Skip slashed FPs
        let fp = FPS.load(storage, fp_btc_pk_hex)?;
        if fp.slashed_height > 0 {
            continue;
        }

        // TODO?: Skip FPs whose registered epochs are not finalised

        // Update staking tx hash by finality provider map
        let mut fp_delegations = FP_DELEGATIONS
            .may_load(storage, fp_btc_pk_hex)?
            .unwrap_or(vec![]);
        fp_delegations.push(staking_tx_hash.as_byte_array().to_vec());
        FP_DELEGATIONS.save(storage, fp_btc_pk_hex, &fp_delegations)?;

        // Update finality provider by staking tx hash reverse map
        let mut delegation_fps = DELEGATION_FPS
            .may_load(storage, staking_tx_hash.as_ref())?
            .unwrap_or(vec![]);
        delegation_fps.push(fp_btc_pk_hex.clone());
        DELEGATION_FPS.save(storage, staking_tx_hash.as_ref(), &delegation_fps)?;

        // Update aggregated voting power by FP
        fps.update(storage, fp_btc_pk_hex, height, |fp_state| {
            let mut fp_state = fp_state.unwrap_or_default();
            fp_state.power = fp_state.power.saturating_add(active_delegation.total_sat);
            Ok::<_, ContractError>(fp_state)
        })?;

        registered_fp = true;
    }

    if !registered_fp {
        return Err(ContractError::FinalityProviderNotRegistered);
    }
    // Add this BTC delegation
    let delegation = BtcDelegation::from(active_delegation);
    DELEGATIONS.save(storage, staking_tx_hash.as_ref(), &delegation)?;

    // Store activated height, if first delegation
    if ACTIVATED_HEIGHT.may_load(storage)?.is_none() {
        ACTIVATED_HEIGHT.save(storage, &(height + 1))?; // Active from the next block onwards
    }

    // TODO: Emit corresponding events

    Ok(())
}

/// handle_undelegation handles undelegation from an active delegation
fn handle_undelegation(
    storage: &mut dyn Storage,
    height: u64,
    undelegation: &UnbondedBtcDelegation,
) -> Result<Event, ContractError> {
    // Basic stateless checks
    undelegation.validate()?;

    let staking_tx_hash = Txid::from_str(&undelegation.staking_tx_hash)?;
    let mut btc_del = DELEGATIONS.load(storage, staking_tx_hash.as_ref())?;

    // TODO: Ensure the BTC delegation is active

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
    // Record event that the BTC delegation becomes unbonded
    let unbonding_event = Event::new("btc_undelegation")
        .add_attribute("staking_tx_hash", staking_tx_hash.to_string())
        .add_attribute("height", height.to_string());

    Ok(unbonding_event)
}

/// handle_slashed_delegation handles undelegation due to slashing from an active delegation
///
fn handle_slashed_delegation(
    storage: &mut dyn Storage,
    height: u64,
    delegation: &SlashedBtcDelegation,
) -> Result<Event, ContractError> {
    // Basic stateless checks
    delegation.validate()?;

    let staking_tx_hash = Txid::from_str(&delegation.staking_tx_hash)?;
    let mut btc_del = DELEGATIONS.load(storage, staking_tx_hash.as_ref())?;

    // TODO: Ensure the BTC delegation is active

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

    // Mark the delegation as slashed
    btc_del.slashed = true;
    DELEGATIONS.save(storage, staking_tx_hash.as_ref(), &btc_del)?;

    // Record event that the BTC delegation becomes unbonded due to slashing at this height
    let slashing_event = Event::new("btc_undelegation_slashed")
        .add_attribute("staking_tx_hash", staking_tx_hash.to_string())
        .add_attribute("height", height.to_string());

    Ok(slashing_event)
}

/// btc_undelegate adds the signature of the unbonding tx signed by the staker to the given BTC
/// delegation
fn btc_undelegate(
    storage: &mut dyn Storage,
    staking_tx_hash: &Txid,
    btc_del: &mut BtcDelegation,
    unbonding_tx_sig: &[u8],
) -> Result<(), ContractError> {
    btc_del.undelegation_info.delegator_unbonding_sig = unbonding_tx_sig.to_vec();

    // Set BTC delegation back to KV store
    DELEGATIONS.save(storage, staking_tx_hash.as_ref(), btc_del)?;

    // TODO? Notify subscriber about this unbonded BTC delegation
    //  - Who are subscribers in this context?
    //  - How to notify them? Emit event?

    // TODO? Record event that the BTC delegation becomes unbonded at this height

    Ok(())
}

/// `compute_active_finality_providers` sorts all finality providers, counts the total voting
/// power of top finality providers, and records them in the contract state
pub fn compute_active_finality_providers(
    storage: &mut dyn Storage,
    env: Env,
    max_active_fps: usize,
) -> Result<(), ContractError> {
    // Sort finality providers by power
    let (finality_providers, running_total): (_, Vec<_>) = fps()
        .idx
        .power
        .range(storage, None, None, Order::Descending)
        .take(max_active_fps)
        .scan(0u64, |acc, item| {
            let (pk_hex, fp_state) = item.ok()?; // Error ends the iteration

            let fp_info = FinalityProviderInfo {
                btc_pk_hex: pk_hex,
                power: fp_state.power,
            };
            *acc += fp_state.power;
            Some((fp_info, *acc))
        })
        .filter(|(fp, _)| {
            // Filter out FPs with no voting power
            fp.power > 0
        })
        .unzip();

    // TODO: Online FPs verification
    // TODO: Filter out slashed / offline / jailed FPs
    // Save the new set of active finality providers
    // TODO: Purge old (height - finality depth) FP_SET entries to avoid bloating the storage
    FP_SET.save(storage, env.block.height, &finality_providers)?;
    // Save the total voting power of the top n finality providers
    let total_power = running_total.last().copied().unwrap_or_default();
    TOTAL_POWER.save(storage, &total_power)?;

    Ok(())
}

/// `slash_finality_provider` slashes a finality provider with the given PK.
/// A slashed finality provider will not have voting power
pub(crate) fn slash_finality_provider(
    store: &mut dyn Storage,
    env: Env,
    fp_btc_pk_hex: &str,
    height: u64,
) -> Result<(), ContractError> {
    // Ensure finality provider exists
    let mut fp = FPS.load(store, fp_btc_pk_hex)?;

    // Check if the finality provider is already slashed
    if fp.slashed_height > 0 {
        return Err(ContractError::FinalityProviderAlreadySlashed(
            fp_btc_pk_hex.to_string(),
        ));
    }
    // Set the finality provider as slashed
    fp.slashed_height = height;

    // Set BTC slashing height (if available from the store)
    // FIXME: Turn this into a hard error
    // return fmt.Errorf("failed to get current BTC tip")
    let btc_height = BTC_HEIGHT.may_load(store, height)?.unwrap_or_default();
    fp.slashed_btc_height = btc_height;

    // Record slashed event. The next `BeginBlock` will consume this event for updating the active
    // FP set.
    // We simply set the FP voting power to zero from the next *processing* height (See NOTE in
    // `handle_finality_signature`)
    fps().update(store, fp_btc_pk_hex, env.block.height + 1, |fp| {
        let mut fp = fp.unwrap_or_default();
        fp.power = 0;
        Ok::<_, ContractError>(fp)
    })?;

    // Save the finality provider back
    FPS.save(store, fp_btc_pk_hex, &fp)?;

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use cosmwasm_std::Binary;

    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};

    use crate::contract::tests::{
        create_new_finality_provider, get_active_btc_delegation, get_params, CREATOR, INIT_ADMIN,
    };
    use crate::contract::{execute, instantiate};
    use crate::msg::{ExecuteMsg, InstantiateMsg};
    use crate::queries;
    use crate::state::staking::BtcUndelegationInfo;

    // Compute staking tx hash of a delegation
    pub(crate) fn staking_tx_hash(del: &BtcDelegation) -> Txid {
        let staking_tx: Transaction = deserialize(&del.staking_tx).unwrap();
        staking_tx.txid()
    }

    #[test]
    fn test_add_fp_unauthorized() {
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

        let new_fp = create_new_finality_provider(1);

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
    fn test_add_fp_admin() {
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
        let new_fp = create_new_finality_provider(1);

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
    fn active_delegation_happy_path() {
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

        let params = get_params();
        PARAMS.save(deps.as_mut().storage, &params).unwrap();

        // Build valid active delegation
        let active_delegation = get_active_btc_delegation();

        // Register one FP first
        let mut new_fp = create_new_finality_provider(1);
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
        let delegation = BtcDelegation::from(&active_delegation);
        let staking_tx_hash_hex = staking_tx_hash(&delegation).to_string();
        let query_res = queries::delegation(deps.as_ref(), staking_tx_hash_hex).unwrap();
        assert_eq!(query_res, delegation);

        // Check that the finality provider power has been updated
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(fp.power, active_delegation.total_sat);
    }

    #[test]
    fn undelegation_works() {
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

        let params = get_params();
        PARAMS.save(deps.as_mut().storage, &params).unwrap();

        // Build valid active delegation
        let active_delegation = get_active_btc_delegation();

        // Register one FP first
        let mut new_fp = create_new_finality_provider(1);
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
        let active_delegation_undelegation = active_delegation.undelegation_info.clone();
        // Compute the staking tx hash
        let delegation = BtcDelegation::from(&active_delegation);
        let staking_tx_hash_hex = staking_tx_hash(&delegation).to_string();

        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex.clone()).unwrap();
        let btc_undelegation = btc_del.undelegation_info;
        assert_eq!(
            btc_undelegation,
            BtcUndelegationInfo {
                unbonding_tx: active_delegation_undelegation.unbonding_tx.to_vec(),
                slashing_tx: active_delegation_undelegation.slashing_tx.to_vec(),
                delegator_unbonding_sig: vec![],
                delegator_slashing_sig: active_delegation_undelegation
                    .delegator_slashing_sig
                    .to_vec(),
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
        let active_delegation_undelegation = active_delegation.undelegation_info;
        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex).unwrap();
        let btc_undelegation = btc_del.undelegation_info;
        assert_eq!(
            btc_undelegation,
            BtcUndelegationInfo {
                unbonding_tx: active_delegation_undelegation.unbonding_tx.into(),
                slashing_tx: active_delegation_undelegation.slashing_tx.into(),
                delegator_unbonding_sig: vec![0x01, 0x02, 0x03],
                delegator_slashing_sig: active_delegation_undelegation
                    .delegator_slashing_sig
                    .into(),
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            }
        );

        // Check the finality provider power has been updated
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(fp.power, 0);
    }

    #[test]
    fn slashed_delegation_works() {
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

        let params = get_params();
        PARAMS.save(deps.as_mut().storage, &params).unwrap();

        // Build valid active delegation
        let active_delegation = get_active_btc_delegation();

        // Register one FP first
        let mut new_fp = create_new_finality_provider(1);
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

        // Check the delegation is active (it has no unbonding sig or is slashed)
        // Compute the staking tx hash
        let delegation = BtcDelegation::from(&active_delegation);
        let staking_tx_hash_hex = staking_tx_hash(&delegation).to_string();
        // Query the delegation
        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex.clone()).unwrap();
        assert!(&btc_del.undelegation_info.delegator_unbonding_sig.is_empty());
        assert!(!btc_del.slashed);

        // Check the finality provider has power
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(fp.power, btc_del.total_sat);

        // Now send the slashed delegation message
        let slashed = SlashedBtcDelegation {
            staking_tx_hash: staking_tx_hash_hex.clone(),
            recovered_fp_btc_sk: "deadbeef".to_string(), // Currently unused
        };

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![],
            unbonded_del: vec![],
            slashed_del: vec![slashed.clone()],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());
        // Check events
        assert_eq!(res.events.len(), 1);
        assert_eq!(res.events[0].ty.as_str(), "btc_undelegation_slashed");
        assert_eq!(res.events[0].attributes.len(), 2);
        assert_eq!(res.events[0].attributes[0].key.as_str(), "staking_tx_hash");
        assert_eq!(
            res.events[0].attributes[0].value.as_str(),
            staking_tx_hash_hex
        );
        assert_eq!(res.events[0].attributes[1].key.as_str(), "height");

        // Check the delegation is not active any more (slashed)
        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex).unwrap();
        assert!(btc_del.slashed);
        // Check the unbonding sig is still empty
        assert!(btc_del.undelegation_info.delegator_unbonding_sig.is_empty());

        // Check the finality provider power has been zeroed (it has only this delegation that was
        // slashed)
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(fp.power, 0);
    }
}
