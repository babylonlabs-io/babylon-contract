use crate::error::ContractError;
use crate::state::config::CONFIG;
use babylon_bindings::BabylonMsg;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use btc_light_client::msg::btc_header::btc_headers_from_info;
use btc_light_client::msg::contract::ExecuteMsg as BtcLightClientExecuteMsg;
use cosmwasm_std::{to_json_binary, DepsMut, Response, WasmMsg};

/// Submit BTC headers to the light client
pub fn submit_headers(
    deps: DepsMut,
    headers: &[BtcHeaderInfo],
) -> Result<Response<BabylonMsg>, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    let contract_addr = cfg
        .btc_light_client
        .ok_or(ContractError::BtcLightClientNotSet {})?
        .to_string();

    let btc_headers = btc_headers_from_info(headers)?;

    let msg = BtcLightClientExecuteMsg::BtcHeaders {
        headers: btc_headers,
    };
    let wasm_msg = WasmMsg::Execute {
        contract_addr,
        msg: to_json_binary(&msg)?,
        funds: vec![],
    };

    Ok(Response::new()
        .add_message(wasm_msg)
        .add_attribute("action", "submit_btc_headers"))
}
