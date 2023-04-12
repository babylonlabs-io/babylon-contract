use cosmwasm_std::{
    to_binary, Deps, DepsMut, Empty, Env, MessageInfo, QueryResponse, Reply, Response, StdResult,
};

use crate::msg::{AccountResponse, InstantiateMsg, QueryMsg};
use crate::state::config;

pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // initialise config
    let cfg = config::Config {
        network: msg.network,
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

/// this is a no-op for now as we don't have any messages
pub fn execute(_deps: DepsMut, _env: Env, _info: MessageInfo, _msg: Empty) -> StdResult<Response> {
    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::Addr;
    use cw_multi_test::{App, ContractWrapper, Executor};

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
        let mut app = App::default();

        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        app.instantiate_contract(
            code_id,
            Addr::unchecked("creator"),
            &InstantiateMsg {
                network: babylon_bitcoin::chain_params::Network::Regtest,
                btc_confirmation_depth: 10,
                checkpoint_finalization_timeout: 100,
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();
    }
}
