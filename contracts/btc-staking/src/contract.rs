use crate::error::ContractError;
use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, FinalityProvider, NewFinalityProvider, SlashedBtcDelegation, SudoMsg,
    UnbondedBtcDelegation,
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
    to_json_binary, Addr, Binary, CustomQuery, Deps, DepsMut, Empty, Env, MessageInfo,
    QueryRequest, QueryResponse, Reply, Response, StdResult, Storage, WasmQuery,
};
use cw2::set_contract_version;
use cw_utils::nonpayable;
use hex::ToHex;
use k256::schnorr::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};
use prost::bytes::Bytes;
use prost::Message;
use std::str::FromStr;

use babylon_contract::state::btc_light_client::BTC_TIP_KEY;

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries;
use crate::state::public_randomness::{PUB_RAND_COMMITS, PUB_RAND_VALUES};
use crate::state::{
    fps, public_randomness, Config, ADMIN, BTC_HEIGHT, CONFIG, DELEGATIONS, DELEGATION_FPS, FPS,
    FP_DELEGATIONS, PARAMS, SIGNATURES,
};
use babylon_apis::finality_api::{PubRandCommit, TendermintProof};
use cw_utils::maybe_addr;

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    mut deps: DepsMut,
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

    let api = deps.api;
    ADMIN.set(deps.branch(), maybe_addr(api, msg.admin.clone())?)?;

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
        QueryMsg::Admin {} => to_json_binary(&ADMIN.query_admin(deps)?).map_err(Into::into),
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
        QueryMsg::FinalityProviderInfo { btc_pk_hex, height } => Ok(to_json_binary(
            &queries::finality_provider_info(deps, btc_pk_hex, height)?,
        )?),
        QueryMsg::FinalityProvidersByPower { start_after, limit } => Ok(to_json_binary(
            &queries::finality_providers_by_power(deps, start_after, limit)?,
        )?),
        QueryMsg::FinalitySignature { btc_pk_hex, height } => Ok(to_json_binary(
            &queries::finality_signature(deps, btc_pk_hex, height)?,
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
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    let api = deps.api;
    match msg {
        ExecuteMsg::UpdateAdmin { admin } => ADMIN
            .execute_update_admin(deps, info, maybe_addr(api, admin)?)
            .map_err(Into::into),
        ExecuteMsg::BtcStaking {
            new_fp,
            active_del,
            slashed_del,
            unbonded_del,
        } => handle_btc_staking(
            deps,
            env,
            &info,
            &new_fp,
            &active_del,
            &slashed_del,
            &unbonded_del,
        ),
        ExecuteMsg::SubmitFinalitySignature {
            fp_pubkey_hex,
            height,
            pub_rand,
            proof,
            block_hash,
            signature,
        } => handle_finality_signature(
            deps,
            env,
            &fp_pubkey_hex,
            height,
            &pub_rand,
            &proof,
            &block_hash,
            &signature,
        ),
        ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex,
            start_height,
            num_pub_rand,
            commitment,
            signature,
        } => handle_public_randomness_commit(
            deps,
            &fp_pubkey_hex,
            start_height,
            num_pub_rand,
            &commitment,
            &signature,
        ),
    }
}

/// handle_btc_staking handles the BTC staking operations.
///
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
            undelegation_info.delegator_unbonding_sig = Binary(unbondind_tx_sig.to_vec());
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

pub fn handle_public_randomness_commit(
    deps: DepsMut,
    fp_pubkey_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
    // Ensure the request contains enough amounts of public randomness
    let min_pub_rand = PARAMS.load(deps.storage)?.min_pub_rand;
    if num_pub_rand < min_pub_rand {
        return Err(ContractError::TooFewPubRand(min_pub_rand, num_pub_rand));
    }
    // TODO: ensure log_2(num_pub_rand) is an integer?

    // Ensure the finality provider is registered
    if !FPS.has(deps.storage, fp_pubkey_hex) {
        return Err(ContractError::FinalityProviderNotFound(
            fp_pubkey_hex.to_string(),
        ));
    }

    let pr_commit = PubRandCommit {
        start_height,
        num_pub_rand,
        commitment: commitment.to_vec(),
    };

    // Verify signature over the list
    verify_commitment_signature(
        fp_pubkey_hex,
        start_height,
        num_pub_rand,
        commitment,
        signature,
    )?;

    // Get last public randomness commitment
    // TODO: allow committing public randomness earlier than existing ones?
    let last_pr_commit =
        public_randomness::get_last_pub_rand_commit(deps.storage, fp_pubkey_hex).ok();

    if let Some(last_pr_commit) = last_pr_commit {
        // Ensure height and start_height do not overlap, i.e., height < start_height
        let last_pr_end_height = last_pr_commit.end_height();
        if start_height <= last_pr_end_height {
            return Err(ContractError::InvalidPubRandHeight(
                start_height,
                last_pr_end_height,
            ));
        }
    }

    // All good, store the given public randomness commitment
    PUB_RAND_COMMITS.save(
        deps.storage,
        (fp_pubkey_hex, pr_commit.start_height),
        &pr_commit,
    )?;

    // TODO: Add events
    Ok(Response::new())
}

fn verify_commitment_signature(
    fp_btc_pk_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    // get BTC public key for verification
    let btc_pk_raw = hex::decode(fp_btc_pk_hex)?;
    let btc_pk = VerifyingKey::from_bytes(&btc_pk_raw)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get signature
    if signature.is_empty() {
        return Err(ContractError::EmptySignature);
    }
    let schnorr_sig =
        Signature::try_from(signature).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get signed message
    let mut msg: Vec<u8> = vec![];
    msg.extend_from_slice(&start_height.to_be_bytes());
    msg.extend_from_slice(&num_pub_rand.to_be_bytes());
    msg.extend_from_slice(commitment);

    // Verify the signature
    btc_pk
        .verify(&msg, &schnorr_sig)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn handle_finality_signature(
    deps: DepsMut,
    env: Env,
    fp_btc_pk_hex: &str,
    height: u64,
    pub_rand: &[u8],
    _proof: &TendermintProof,
    _block_hash: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
    // Ensure the finality provider exists
    FPS.load(deps.storage, fp_btc_pk_hex)?;

    // TODO: Ensure the finality provider is not slashed at this time point
    // NOTE: It's possible that the finality provider equivocates for height h, and the signature is
    // processed at height h' > h. In this case:
    // - We should reject any new signature from this finality provider, since it's known to be adversarial.
    // - We should set its voting power since height h'+1 to be zero, for to the same reason.
    // - We should NOT set its voting power between [h, h'] to be zero, since
    //   - Babylon BTC staking ensures safety upon 2f+1 votes, *even if* f of them are adversarial.
    //     This is because as long as a block gets 2f+1 votes, any other block with 2f+1 votes has a
    //     f+1 quorum intersection with this block, contradicting the assumption and leading to
    //     the safety proof.
    //     This ensures slashable safety together with EOTS, thus does not undermine Babylon's security guarantee.
    //   - Due to this reason, when tallying a block, Babylon finalises this block upon 2f+1 votes. If we
    //     modify voting power table in the history, some finality decisions might be contradicting to the
    //     signature set and voting power table.
    //   - To fix the above issue, Babylon has to allow finalised and not-finalised blocks. However,
    //     this means Babylon will lose safety under an adaptive adversary corrupting even 1
    //     finality provider. It can simply corrupt a new finality provider and equivocate a
    //     historical block over and over again, making a previous block not finalisable forever.

    // Ensure the finality provider has voting power at this height
    fps()
        .may_load_at_height(deps.storage, fp_btc_pk_hex, height)?
        .ok_or_else(|| ContractError::NoVotingPower(fp_btc_pk_hex.to_string(), height))?;

    // Ensure the signature is not empty
    if signature.is_empty() {
        return Err(ContractError::EmptySignature);
    }
    // Ensure the height is proper
    if env.block.height < height {
        return Err(ContractError::HeightTooHigh);
    }
    // Ensure the finality provider has not cast the same vote yet
    let existing_sig = SIGNATURES.may_load(deps.storage, (height, fp_btc_pk_hex))?;
    match existing_sig {
        Some(existing_sig) if existing_sig == signature => {
            deps.api.debug(&format!("Received duplicated finality vote. Height: {height}, Finality Provider: {fp_btc_pk_hex}"));
            // Exactly the same vote already exists, return success to the provider
            return Ok(Response::new());
        }
        _ => {}
    }

    // TODO: Find the public randomness commitment for this height from this finality provider
    // let _pr_commit = get_pub_rand_commit_for_height(deps.storage, fp_btc_pk_hex, height)?;

    // TODO: Verify the finality signature message w.r.t. the public randomness commitment
    // including the public randomness inclusion proof and the finality signature
    // verify_finality_signature(signature, pr_commit)?;

    // The public randomness value is good, save it.
    // TODO?: Don't save public randomness values, to save storage space
    PUB_RAND_VALUES.save(deps.storage, (fp_btc_pk_hex, height), &pub_rand.to_vec())?;

    // TODO: Verify whether the voted block is a fork or not
    /*
    indexedBlock, err := ms.GetBlock(ctx, req.BlockHeight)
    if err != nil {
        return nil, err
    }
    if !bytes.Equal(indexedBlock.AppHash, req.BlockAppHash) {
        // the finality provider votes for a fork!

        // construct evidence
        evidence := &types.Evidence{
            FpBtcPk:              req.FpBtcPk,
            BlockHeight:          req.BlockHeight,
            PubRand:              req.PubRand,
            CanonicalAppHash:     indexedBlock.AppHash,
            CanonicalFinalitySig: nil,
            ForkAppHash:          req.BlockAppHash,
            ForkFinalitySig:      signature,
        }

        // if this finality provider has also signed canonical block, slash it
        canonicalSig, err := ms.GetSig(ctx, req.BlockHeight, fpPK)
        if err == nil {
            //set canonical sig
            evidence.CanonicalFinalitySig = canonicalSig
            // slash this finality provider, including setting its voting power to
            // zero, extracting its BTC SK, and emit an event
            ms.slashFinalityProvider(ctx, req.FpBtcPk, evidence)
        }

        // save evidence
        ms.SetEvidence(ctx, evidence)

        // NOTE: we should NOT return error here, otherwise the state change triggered in this tx
        // (including the evidence) will be rolled back
        return &types.MsgAddFinalitySigResponse{}, nil
    }
    */

    // This signature is good, save the vote to the store
    SIGNATURES.save(deps.storage, (height, fp_btc_pk_hex), &signature.to_vec())?;

    // TODO: If this finality provider has signed the canonical block before, slash it via
    // extracting its secret key, and emit an event
    /*
    if ms.HasEvidence(ctx, req.FpBtcPk, req.BlockHeight) {
        // the finality provider has voted for a fork before!
        // If this evidence is at the same height as this signature, slash this finality provider

        // get evidence
        evidence, err := ms.GetEvidence(ctx, req.FpBtcPk, req.BlockHeight)
        if err != nil {
            panic(fmt.Errorf("failed to get evidence despite HasEvidence returns true"))
        }

        // set canonical sig to this evidence
        evidence.CanonicalFinalitySig = signature
        ms.SetEvidence(ctx, evidence)

        // slash this finality provider, including setting its voting power to
        // zero, extracting its BTC SK, and emit an event
        ms.slashFinalityProvider(ctx, req.FpBtcPk, evidence)
    }
    */

    // TODO: Add events
    Ok(Response::new())
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
        from_json,
        testing::{mock_dependencies, mock_env, mock_info},
        Decimal,
    };
    use cw_controllers::AdminResponse;
    use hex::ToHex;
    use test_utils::{get_btc_delegation_and_params, get_pub_rand_commit};

    const CREATOR: &str = "creator";
    const INIT_ADMIN: &str = "initial_admin";
    const NEW_ADMIN: &str = "new_admin";

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
            staking_tx: Binary(del.staking_tx.to_vec()),
            slashing_tx: Binary(del.slashing_tx.to_vec()),
            delegator_slashing_sig: Binary(vec![]),
            covenant_sigs: del
                .covenant_sigs
                .iter()
                .map(|cov_sig| CovenantAdaptorSignatures {
                    cov_pk: Binary(cov_sig.cov_pk.to_vec()),
                    adaptor_sigs: cov_sig
                        .adaptor_sigs
                        .iter()
                        .map(|adaptor_sig| Binary(adaptor_sig.to_vec()))
                        .collect(),
                })
                .collect(),
            staking_output_idx: del.staking_output_idx,
            unbonding_time: del.unbonding_time,
            undelegation_info: Some(BtcUndelegationInfo {
                unbonding_tx: Binary(btc_undelegation.unbonding_tx.to_vec()),
                slashing_tx: Binary(btc_undelegation.slashing_tx.to_vec()),
                delegator_unbonding_sig: Binary(vec![]),
                delegator_slashing_sig: Binary(btc_undelegation.delegator_slashing_sig.to_vec()),
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            }),
            params_version: del.params_version,
        }
    }

    /// Build a public randomness commit message
    pub(crate) fn get_public_randomness_commitment() -> (String, PubRandCommit, Vec<u8>) {
        let pub_rand_commitment_msg = get_pub_rand_commit();

        (
            pub_rand_commitment_msg.fp_btc_pk.encode_hex(),
            PubRandCommit {
                start_height: pub_rand_commitment_msg.start_height,
                num_pub_rand: pub_rand_commitment_msg.num_pub_rand,
                commitment: pub_rand_commitment_msg.commitment.to_vec(),
            },
            pub_rand_commitment_msg.sig.to_vec(),
        )
    }

    pub(crate) fn create_new_finality_provider() -> NewFinalityProvider {
        NewFinalityProvider {
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
                babylon_sig: Binary(vec![]),
                btc_sig: Binary(vec![]),
            }),
            consumer_id: "osmosis-1".to_string(),
        }
    }

    #[test]
    fn instantiate_without_admin() {
        let mut deps = mock_dependencies();

        // Create an InstantiateMsg with admin set to None
        let msg = InstantiateMsg {
            params: None,
            admin: None, // No admin provided
        };

        let info = mock_info(CREATOR, &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Query the admin to verify it was not set
        let res = ADMIN.query_admin(deps.as_ref()).unwrap();
        assert_eq!(None, res.admin);
    }

    #[test]
    fn instantiate_with_admin() {
        let mut deps = mock_dependencies();

        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let msg = InstantiateMsg {
            params: None,
            admin: Some(INIT_ADMIN.into()), // Admin provided
        };

        let info = mock_info(CREATOR, &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was set correctly
        // This uses the assert_admin helper function provided by the Admin crate
        ADMIN
            .assert_admin(deps.as_ref(), &Addr::unchecked(INIT_ADMIN))
            .unwrap();

        // ensure the admin is queryable as well
        let res = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
        let admin: AdminResponse = from_json(res).unwrap();
        assert_eq!(admin.admin.unwrap(), INIT_ADMIN)
    }

    #[test]
    fn test_update_admin() {
        let mut deps = mock_dependencies();

        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let instantiate_msg = InstantiateMsg {
            params: None,
            admin: Some(INIT_ADMIN.into()), // Admin provided
        };

        let info = mock_info(CREATOR, &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was set correctly
        ADMIN
            .assert_admin(deps.as_ref(), &Addr::unchecked(INIT_ADMIN))
            .unwrap();

        // Update the admin to NEW_ADMIN
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: Some(NEW_ADMIN.to_string()),
        };

        // Execute the UpdateAdmin message with a non-admin info
        let non_admin_info = mock_info("non_admin", &[]);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            non_admin_info,
            update_admin_msg.clone(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ContractError::Admin(cw_controllers::AdminError::NotAdmin {})
        );

        // Execute the UpdateAdmin message with the initial admin info
        let admin_info = mock_info(INIT_ADMIN, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was updated correctly
        ADMIN
            .assert_admin(deps.as_ref(), &Addr::unchecked(NEW_ADMIN))
            .unwrap();
    }

    #[test]
    fn test_btc_staking_add_fp_unauthorized() {
        let mut deps = mock_dependencies();
        let info = mock_info(CREATOR, &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: Some(INIT_ADMIN.into()), // Admin provided
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
        let other_info = mock_info("other", &[]);
        let err = execute(deps.as_mut(), mock_env(), other_info, msg.clone()).unwrap_err();
        assert_eq!(err, ContractError::Unauthorized);
    }

    #[test]
    fn test_btc_staking_add_fp_admin() {
        let mut deps = mock_dependencies();
        let info = mock_info(CREATOR, &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: Some(INIT_ADMIN.into()), // Admin provided
            },
        )
        .unwrap();

        let admin_info = mock_info(INIT_ADMIN, &[]); // Mock info for the admin
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
        let info = mock_info(CREATOR, &[]);

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
        let info = mock_info(CREATOR, &[]);

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
                delegator_unbonding_sig: Binary(vec![]),
                delegator_slashing_sig: active_delegation_undelegation.delegator_slashing_sig,
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            }
        );

        // Now send the undelegation message
        let undelegation = UnbondedBtcDelegation {
            staking_tx_hash: staking_tx_hash_hex.clone(),
            unbonding_tx_sig: Binary(vec![0x01, 0x02, 0x03]), // TODO: Use a proper signature
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
                delegator_unbonding_sig: Binary(vec![0x01, 0x02, 0x03]),
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

    #[test]
    fn commit_public_randomness_works() {
        let mut deps = mock_dependencies();
        let info = mock_info(CREATOR, &[]);

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

        // Read public randomness commitment test data
        let (pk_hex, pub_rand, signature) = get_public_randomness_commitment();

        // Register one FP with a valid pubkey first
        let mut new_fp = create_new_finality_provider();
        new_fp.btc_pk_hex.clone_from(&pk_hex);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Now commit the public randomness for it
        let msg = ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex: pk_hex,
            start_height: pub_rand.start_height,
            num_pub_rand: pub_rand.num_pub_rand,
            commitment: Binary(pub_rand.commitment),
            signature: Binary(signature),
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());
    }
}
