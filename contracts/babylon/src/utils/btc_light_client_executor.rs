use crate::error::ContractError;
use crate::state::config::CONFIG;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use btc_light_client::msg::btc_header::btc_headers_from_info;
use btc_light_client::msg::contract::ExecuteMsg as BtcLightClientExecuteMsg;
use cosmwasm_std::{to_json_binary, DepsMut, WasmMsg};

pub fn new_btc_headers_msg(
    deps: &mut DepsMut,
    headers: &[BtcHeaderInfo],
) -> Result<WasmMsg, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    let contract_addr = cfg
        .btc_light_client
        .ok_or(ContractError::BtcLightClientNotSet {})?
        .to_string();

    let btc_headers = btc_headers_from_info(headers)?;

    let base_header = headers.first().ok_or(ContractError::BtcHeaderEmpty {})?;
    let first_work = hex::encode(base_header.work.as_ref());
    let first_height = base_header.height;

    let msg = BtcLightClientExecuteMsg::BtcHeaders {
        headers: btc_headers,
        first_work: Some(first_work),
        first_height: Some(first_height),
    };
    let wasm_msg = WasmMsg::Execute {
        contract_addr,
        msg: to_json_binary(&msg)?,
        funds: vec![],
    };

    Ok(wasm_msg)
}
