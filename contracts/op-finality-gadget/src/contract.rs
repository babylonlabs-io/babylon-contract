use crate::error::ContractError;
use crate::finality::{handle_finality_signature, handle_public_randomness_commit};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::config::{ADMIN, CONSUMER_CHAIN_ID};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw_utils::maybe_addr;

use babylon_apis::queries::BabylonQueryWrapper;

pub fn instantiate(
    mut deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let admin_addr = maybe_addr(deps.api, Some(msg.admin))?;

    ADMIN.set(deps.branch(), admin_addr)?;

    CONSUMER_CHAIN_ID.save(deps.storage, &msg.consumer_id)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

pub fn query(_deps: Deps<BabylonQueryWrapper>, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    unimplemented!();
}

pub fn execute(
    deps: DepsMut<BabylonQueryWrapper>,
    env: Env,
    _info: MessageInfo,
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
    }
}
