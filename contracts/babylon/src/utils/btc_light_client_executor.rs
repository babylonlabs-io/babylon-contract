use crate::error::ContractError;
use crate::state::config::CONFIG;
use babylon_bindings::BabylonMsg;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use btc_light_client::msg::btc_header::btc_headers_from_info;
use btc_light_client::msg::contract::ExecuteMsg as BtcLightClientExecuteMsg;
use btc_light_client::utils::btc_light_client::total_work;
use cosmwasm_std::{to_json_binary, DepsMut, Response, WasmMsg};

/// Submit BTC headers to the light client
pub fn submit_headers(
    deps: &mut DepsMut,
    headers: &[BtcHeaderInfo],
) -> Result<Response<BabylonMsg>, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    let contract_addr = cfg
        .btc_light_client
        .ok_or(ContractError::BtcLightClientNotSet {})?
        .to_string();

    let btc_headers = btc_headers_from_info(headers)?;

    let base_header = headers.first().ok_or(ContractError::BtcHeaderEmpty {})?;
    let base_work = total_work(base_header.work.as_ref())?.to_be_bytes();
    let base_height = base_header.height;

    let msg = BtcLightClientExecuteMsg::BtcHeaders {
        headers: btc_headers,
        base_work: Some(base_work),
        base_height: Some(base_height),
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
