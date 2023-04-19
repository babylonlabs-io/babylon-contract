use cosmwasm_std::{
    to_binary, Deps, DepsMut, Empty, Env, MessageInfo, QueryResponse, Reply, Response, StdResult,
};

use crate::bindings::try_report_fork_header;
use crate::msg::bindings::BabylonMsg;
use crate::msg::contract::{AccountResponse, ContractMsg, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::config;

pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    msg.validate()?;

    // initialise config
    let cfg = config::Config {
        network: msg.network,
        babylon_tag: msg.babylon_tag.as_bytes().to_vec(),
        btc_confirmation_depth: msg.btc_confirmation_depth,
        checkpoint_finalization_timeout: msg.checkpoint_finalization_timeout,
    };
    config::init(deps.storage, cfg);

    Ok(Response::new().add_attribute("action", "instantiate"))
}

pub fn reply(_deps: DepsMut, _env: Env, _reply: Reply) -> StdResult<Response> {
    Ok(Response::default())
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<QueryResponse> {
    match msg {
        QueryMsg::Account { channel_id } => to_binary(&query::account(deps, channel_id)?),
    }
}

mod query {
    use super::*;

    pub fn account(_deps: Deps, _channel_id: String) -> StdResult<AccountResponse> {
        let resp = AccountResponse {
            account: Some("TODO: replace me".to_owned()),
        };

        Ok(resp)
    }
}

/// this is a no-op just to test how this integrates with wasmd
pub fn migrate(_deps: DepsMut, _env: Env, _msg: Empty) -> StdResult<Response> {
    Ok(Response::default())
}

pub fn execute(
    _deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response<BabylonMsg>> {
    // TESTING: trigger ForkHeader to print stuff at Cosmos zone side
    // TODO: remember to remove
    match msg {
        crate::msg::contract::ExecuteMsg::Placeholder {} => {
            Ok(try_report_fork_header(env).unwrap())
        }
    }

    // Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    const CREATOR: &str = "creator";

    #[test]
    fn test_deserialize_btc_header() {
        // https://babylon.explorers.guru/transaction/8CEC6D605A39378F560C2134ABC931AE7DED0D055A6655B82CC5A31D5DA0BE26
        let btc_header_hex = "00400720b2559c9eb13821d6df53ffab9ddf3a645c559f030cac050000000000000000001ff22ffaa13c41df6aebc4b9b09faf328748c3a45772b6a4c4da319119fd5be3b53a1964817606174cc4c4b0";
        let btc_header_bytes = hex::decode(btc_header_hex).unwrap();
        let _btc_header: babylon_bitcoin::BlockHeader =
            babylon_bitcoin::deserialize(&btc_header_bytes).unwrap();
    }

    #[test]
    fn instantiate_works() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            network: babylon_bitcoin::chain_params::Network::Regtest,
            babylon_tag: "bbn0".to_string(), // TODO: use hex for encoding/decoding babylon tag
            btc_confirmation_depth: 10,
            checkpoint_finalization_timeout: 100,
        };
        let info = mock_info(CREATOR, &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }
}
