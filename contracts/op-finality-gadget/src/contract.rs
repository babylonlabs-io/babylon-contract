use crate::error::ContractError;
use crate::exec::admin::set_enabled;
use crate::exec::finality::{handle_finality_signature, handle_public_randomness_commit};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries::{query_block_votes, query_config, query_last_pub_rand_commit};
use crate::state::config::{Config, ADMIN, CONFIG, IS_ENABLED};
use cosmwasm_std::{
    to_json_binary, Deps, DepsMut, Env, MessageInfo, QueryResponse, Response, StdResult,
};

pub fn instantiate(
    mut deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let api = deps.api;
    ADMIN.set(deps.branch(), Some(api.addr_validate(&msg.admin)?))?;
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

// Most logic copied from contracts/btc-staking/src/contract.rs
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

    #[test]
    fn instantiate_works() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let consumer_id = "op".to_string();
        let activated_height = 1000;

        // Create an InstantiateMsg with admin set to init_admin
        let msg = InstantiateMsg {
            admin: init_admin.to_string(),
            consumer_id,
            activated_height,
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Assert that no messages were returned
        assert_eq!(0, res.messages.len());

        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // ensure the admin is queryable as well
        let res = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
        let admin: AdminResponse = from_json(res).unwrap();
        assert_eq!(admin.admin.unwrap(), init_admin.as_str())
    }
}
