use crate::error::ContractError;
use crate::exec::admin::set_enabled;
use crate::exec::finality::{
    handle_finality_signature, handle_public_randomness_commit, whitelist_forked_blocks,
};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries::{
    query_block_voters, query_config, query_first_pub_rand_commit, query_forked_blocks,
    query_forked_blocks_in_range, query_is_block_forked, query_last_pub_rand_commit,
};
use crate::state::config::{Config, ADMIN, CONFIG, IS_ENABLED};
use crate::state::finality::FORKED_BLOCKS;
use cosmwasm_std::{
    to_json_binary, Deps, DepsMut, Env, MessageInfo, QueryResponse, Response, StdResult,
};
use cw_controllers::AdminError;

pub fn instantiate(
    mut deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let api = deps.api;
    ADMIN.set(deps.branch(), Some(api.addr_validate(&msg.admin)?))?;
    IS_ENABLED.save(deps.storage, &msg.is_enabled)?;

    let config = Config {
        consumer_id: msg.consumer_id,
    };
    CONFIG.save(deps.storage, &config)?;

    let forked_blocks: Vec<(u64, u64)> = vec![];
    FORKED_BLOCKS.save(deps.storage, &forked_blocks)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<QueryResponse, ContractError> {
    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&query_config(deps)?)?),
        QueryMsg::Admin {} => Ok(to_json_binary(&ADMIN.query_admin(deps)?)?),
        QueryMsg::BlockVoters { height, hash } => {
            Ok(to_json_binary(&query_block_voters(deps, height, hash)?)?)
        }
        QueryMsg::FirstPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &query_first_pub_rand_commit(deps.storage, &btc_pk_hex)?,
        )?),
        QueryMsg::LastPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &query_last_pub_rand_commit(deps.storage, &btc_pk_hex)?,
        )?),
        QueryMsg::ForkedBlocks {} => Ok(to_json_binary(&query_forked_blocks(deps)?)?),
        QueryMsg::IsBlockForked { height } => {
            Ok(to_json_binary(&query_is_block_forked(deps, height)?)?)
        }
        QueryMsg::ForkedBlocksInRange { start, end } => Ok(to_json_binary(
            &query_forked_blocks_in_range(deps, start, end)?,
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
    let api = deps.api;

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
        ExecuteMsg::WhitelistForkedBlocks { forked_blocks } => {
            whitelist_forked_blocks(deps, info, forked_blocks)
        }
        ExecuteMsg::SetEnabled { enabled } => set_enabled(deps, info, enabled),
        ExecuteMsg::UpdateAdmin { admin } => ADMIN
            .execute_update_admin(deps, info, Some(api.addr_validate(&admin)?))
            .map_err(|err| match err {
                AdminError::Std(e) => ContractError::StdError(e),
                AdminError::NotAdmin {} => ContractError::Unauthorized,
            }),
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
    const NEW_ADMIN: &str = "new_admin";

    #[test]
    fn instantiate_works() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let consumer_id = "op".to_string();

        // Create an InstantiateMsg with admin set to init_admin
        let msg = InstantiateMsg {
            admin: init_admin.to_string(),
            consumer_id,
            is_enabled: true,
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

    #[test]
    fn test_update_admin() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);

        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(), // Admin provided
            consumer_id: "op-stack-l2-11155420".to_string(),
            is_enabled: true,
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
            admin: new_admin.to_string(),
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
        assert_eq!(err, ContractError::Unauthorized);

        // Execute the UpdateAdmin message with the initial admin info
        let admin_info = message_info(&init_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was updated correctly
        ADMIN.assert_admin(deps.as_ref(), &new_admin).unwrap();
    }
}
