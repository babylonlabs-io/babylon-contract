use crate::error::ContractError;
use crate::exec::admin::set_enabled;
use crate::exec::finality::{handle_finality_signature, handle_public_randomness_commit};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries::{query_block_votes, query_config, query_last_pub_rand_commit};
use crate::state::config::{Config, ADMIN, CONFIG, IS_ENABLED};
use cosmwasm_std::{
    to_json_binary, Deps, DepsMut, Env, MessageInfo, QueryResponse, Response, StdResult,
};
use cw_utils::maybe_addr;

pub fn instantiate(
    mut deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let api = deps.api;
    ADMIN.set(deps.branch(), maybe_addr(api, Some(msg.admin))?)?;
    IS_ENABLED.save(deps.storage, &false)?;

    let config = Config {
        consumer_id: msg.consumer_id,
        activated_height: msg.activated_height,
    };
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<QueryResponse, ContractError> {
    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&query_config(deps)?)?),
        QueryMsg::Admin {} => Ok(to_json_binary(&ADMIN.query_admin(deps)?)?),
        QueryMsg::BlockVotes { height, hash } => {
            Ok(to_json_binary(&query_block_votes(deps, height, hash)?)?)
        }
        QueryMsg::LastPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &query_last_pub_rand_commit(deps.storage, &btc_pk_hex)?,
        )?),
        QueryMsg::IsEnabled {} => Ok(to_json_binary(&IS_ENABLED.load(deps.storage)?)?),
    }
}

pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
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
        ExecuteMsg::SetEnabled { enabled } => set_enabled(deps, info, enabled),
    }
}
