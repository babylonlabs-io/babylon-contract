use crate::error::ContractError;
use crate::finality::{
    compute_active_finality_providers, distribute_rewards_fps, handle_finality_signature,
    handle_public_randomness_commit,
};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::config::{Config, ADMIN, CONFIG, PARAMS};
use crate::state::finality::{REWARDS, TOTAL_REWARDS};
use crate::{finality, queries, state};
use babylon_apis::btc_staking_api::RewardInfo;
use babylon_apis::finality_api::SudoMsg;
use babylon_bindings::BabylonMsg;
use btc_staking::msg::ActivatedHeightResponse;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    attr, coins, to_json_binary, Addr, CustomQuery, Deps, DepsMut, Empty, Env, MessageInfo, Order,
    QuerierWrapper, QueryRequest, QueryResponse, Reply, Response, StdResult, Uint128, WasmMsg,
    WasmQuery,
};
use cw2::set_contract_version;
use cw_utils::{maybe_addr, nonpayable};

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

    // Query blocks per year from the chain's mint module
    let blocks_per_year = get_blocks_per_year(&mut deps)?;
    let config = Config {
        denom,
        blocks_per_year,
        babylon: info.sender,
        staking: Addr::unchecked("UNSET"), // To be set later, through `UpdateStaking`
    };
    CONFIG.save(deps.storage, &config)?;

    let api = deps.api;
    ADMIN.set(deps.branch(), maybe_addr(api, msg.admin.clone())?)?;

    let params = msg.params.unwrap_or_default();
    PARAMS.save(deps.storage, &params)?;
    // initialize storage, so no issue when reading for the first time
    TOTAL_REWARDS.save(deps.storage, &Uint128::zero())?;

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("action", "instantiate"))
}

/// Queries the chain's blocks per year using the mint Params Grpc query
fn get_blocks_per_year(deps: &mut DepsMut) -> Result<u64, ContractError> {
    let blocks_per_year;
    #[cfg(any(test, all(feature = "library", not(target_arch = "wasm32"))))]
    {
        let _ = deps;
        blocks_per_year = 60 * 60 * 24 * 365 / 6; // Default / hardcoded value for tests
    }
    #[cfg(not(any(test, all(feature = "library", not(target_arch = "wasm32")))))]
    {
        let res = deps.querier.query_grpc(
            "/cosmos.mint.v1beta1.Query/Params".into(),
            cosmwasm_std::Binary::new("".into()),
        )?;
        // Deserialize protobuf
        let res_decoded = anybuf::Bufany::deserialize(&res).unwrap();
        // See https://github.com/cosmos/cosmos-sdk/blob/8bfcf554275c1efbb42666cc8510d2da139b67fa/proto/cosmos/mint/v1beta1/query.proto#L35-L36
        let res_params = res_decoded.message(1).unwrap();
        // See https://github.com/cosmos/cosmos-sdk/blob/8bfcf554275c1efbb42666cc8510d2da139b67fa/proto/cosmos/mint/v1beta1/mint.proto#L60-L61
        // to see from where the field number comes from
        blocks_per_year = res_params
            .uint64(6)
            .ok_or(ContractError::MissingBlocksPerYear {})?;
    }
    Ok(blocks_per_year)
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
        QueryMsg::FinalitySignature { btc_pk_hex, height } => Ok(to_json_binary(
            &queries::finality_signature(deps, btc_pk_hex, height)?,
        )?),
        QueryMsg::PubRandCommit {
            btc_pk_hex,
            start_after,
            limit,
            reverse,
        } => Ok(to_json_binary(
            &state::public_randomness::get_pub_rand_commit(
                deps.storage,
                &btc_pk_hex,
                start_after,
                limit,
                reverse,
            )?,
        )?),
        QueryMsg::FirstPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &state::public_randomness::get_first_pub_rand_commit(deps.storage, &btc_pk_hex)?,
        )?),
        QueryMsg::LastPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &state::public_randomness::get_last_pub_rand_commit(deps.storage, &btc_pk_hex)?,
        )?),
        QueryMsg::Block { height } => Ok(to_json_binary(&queries::block(deps, height)?)?),
        QueryMsg::Blocks {
            start_after,
            limit,
            finalised,
            reverse,
        } => Ok(to_json_binary(&queries::blocks(
            deps,
            start_after,
            limit,
            finalised,
            reverse,
        )?)?),
        QueryMsg::Evidence { btc_pk_hex, height } => Ok(to_json_binary(&queries::evidence(
            deps, btc_pk_hex, height,
        )?)?),
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
        ExecuteMsg::UpdateStaking { staking } => handle_update_staking(deps, info, staking),
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

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(
    mut deps: DepsMut,
    env: Env,
    msg: SudoMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    match msg {
        SudoMsg::BeginBlock { .. } => handle_begin_block(&mut deps, env),
        SudoMsg::EndBlock {
            hash_hex,
            app_hash_hex,
        } => handle_end_block(&mut deps, env, &hash_hex, &app_hash_hex),
    }
}

fn handle_update_staking(
    deps: DepsMut,
    info: MessageInfo,
    staking_addr: String,
) -> Result<Response<BabylonMsg>, ContractError> {
    let mut cfg = CONFIG.load(deps.storage)?;
    if info.sender != cfg.babylon && !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }
    cfg.staking = deps.api.addr_validate(&staking_addr)?;
    CONFIG.save(deps.storage, &cfg)?;

    let attributes = vec![
        attr("action", "update_btc_staking"),
        attr("staking", staking_addr),
        attr("sender", info.sender),
    ];
    Ok(Response::new().add_attributes(attributes))
}

fn handle_begin_block(deps: &mut DepsMut, env: Env) -> Result<Response<BabylonMsg>, ContractError> {
    // Distribute rewards
    distribute_rewards_fps(deps, &env)?;

    // Compute active finality provider set
    let max_active_fps = PARAMS.load(deps.storage)?.max_active_finality_providers as usize;
    compute_active_finality_providers(deps, env.block.height, max_active_fps)?;

    // TODO: Add events
    Ok(Response::new())
}

fn handle_end_block(
    deps: &mut DepsMut,
    env: Env,
    _hash_hex: &str,
    app_hash_hex: &str,
) -> Result<Response<BabylonMsg>, ContractError> {
    // If the BTC staking protocol is activated i.e. there exists a height where at least one
    // finality provider has voting power, start indexing and tallying blocks
    let cfg = CONFIG.load(deps.storage)?;
    let mut res = Response::new();
    let activated_height = get_activated_height(&cfg.staking, &deps.querier)?;
    if activated_height > 0 {
        // Index the current block
        let ev = finality::index_block(deps, env.block.height, &hex::decode(app_hash_hex)?)?;
        res = res.add_event(ev);
        // Tally all non-finalised blocks
        let (msg, events) = finality::tally_blocks(deps, &env, activated_height)?;
        if let Some(msg) = msg {
            res = res.add_message(msg);
        }
        res = res.add_events(events);
    }

    // On an epoch boundary, send rewards for distribution.
    // Rewards are sent to the staking contract for distribution over delegators
    let params = PARAMS.load(deps.storage)?;
    if env.block.height > 0 && env.block.height % params.epoch_length == 0 {
        let rewards = TOTAL_REWARDS.load(deps.storage)?;
        if rewards.u128() > 0 {
            let (fp_rewards, wasm_msg) = send_rewards_msg(deps, rewards.u128(), &cfg)?;
            res = res.add_message(wasm_msg);
            // Zero out individual rewards
            for reward in fp_rewards {
                REWARDS.remove(deps.storage, &reward.fp_pubkey_hex);
            }
            // Zero out total rewards
            TOTAL_REWARDS.save(deps.storage, &Uint128::zero())?;
        }
    }
    Ok(res)
}

// Sends rewards to the staking contract for distribution over delegators
fn send_rewards_msg(
    deps: &mut DepsMut,
    rewards: u128,
    cfg: &Config,
) -> Result<(Vec<RewardInfo>, WasmMsg), ContractError> {
    // Get the pending rewards distribution
    let fp_rewards = REWARDS
        .range(deps.storage, None, None, Order::Ascending)
        .filter(|item| {
            if let Ok((_, reward)) = item {
                reward.u128() > 0
            } else {
                true // don't filter errors
            }
        })
        .map(|item| {
            let (fp_pubkey_hex, reward) = item?;
            Ok(babylon_apis::btc_staking_api::RewardInfo {
                fp_pubkey_hex,
                reward,
            })
        })
        .collect::<StdResult<Vec<_>>>()?;
    // The rewards are sent to the BTC staking contract for further distribution
    let msg = btc_staking::msg::ExecuteMsg::DistributeRewards {
        fp_distribution: fp_rewards.clone(),
    };
    let wasm_msg = WasmMsg::Execute {
        contract_addr: cfg.staking.to_string(),
        msg: to_json_binary(&msg)?,
        funds: coins(rewards, cfg.denom.as_str()),
    };
    Ok((fp_rewards, wasm_msg))
}

pub fn get_activated_height(staking_addr: &Addr, querier: &QuerierWrapper) -> StdResult<u64> {
    // TODO: Use a raw query
    let query = encode_smart_query(
        staking_addr,
        &btc_staking::msg::QueryMsg::ActivatedHeight {},
    )?;
    let res: ActivatedHeightResponse = querier.query(&query)?;
    Ok(res.height)
}

pub(crate) fn encode_smart_query<Q: CustomQuery>(
    addr: &Addr,
    msg: &btc_staking::msg::QueryMsg,
) -> StdResult<QueryRequest<Q>> {
    Ok(WasmQuery::Smart {
        contract_addr: addr.to_string(),
        msg: to_json_binary(&msg)?,
    }
    .into())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use cosmwasm_std::{
        from_json,
        testing::{message_info, mock_dependencies, mock_env},
    };
    use cw_controllers::AdminResponse;

    pub(crate) const CREATOR: &str = "creator";
    pub(crate) const INIT_ADMIN: &str = "initial_admin";
    const NEW_ADMIN: &str = "new_admin";

    #[test]
    fn instantiate_without_admin() {
        let mut deps = mock_dependencies();

        // Create an InstantiateMsg with admin set to None
        let msg = InstantiateMsg {
            params: None,
            admin: None, // No admin provided
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

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
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let msg = InstantiateMsg {
            params: None,
            admin: Some(init_admin.to_string()), // Admin provided
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was set correctly
        // This uses the assert_admin helper function provided by the Admin crate
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // ensure the admin is queryable as well
        let res = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
        let admin: AdminResponse = from_json(res).unwrap();
        assert_eq!(admin.admin.unwrap(), init_admin.as_str())
    }

    #[test]
    fn test_update_admin() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);

        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let instantiate_msg = InstantiateMsg {
            params: None,
            admin: Some(init_admin.to_string()), // Admin provided
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was set correctly
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // Update the admin to new_admin
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: Some(new_admin.to_string()),
        };

        // Execute the UpdateAdmin message with non-admin info
        let non_admin_info = message_info(&deps.api.addr_make("non_admin"), &[]);
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
        let admin_info = message_info(&init_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was updated correctly
        ADMIN.assert_admin(deps.as_ref(), &new_admin).unwrap();
    }
}
