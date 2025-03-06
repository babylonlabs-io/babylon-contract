use crate::error::ContractError;
use crate::state::config::CONFIG;
use btc_light_client::msg::btc_header::{BtcHeaderResponse, BtcHeadersResponse};
use cosmwasm_std::Deps;

/// Get the BTC light client contract address
fn get_contract_addr(deps: Deps) -> Result<String, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    Ok(cfg
        .btc_light_client
        .ok_or(ContractError::BtcLightClientNotSet {})?
        .to_string())
}

/// Query the base header from the BTC light client
pub fn query_base_header(deps: Deps) -> Result<BtcHeaderResponse, ContractError> {
    let contract_addr = get_contract_addr(deps)?;
    let msg = btc_light_client::msg::contract::QueryMsg::BtcBaseHeader {};
    let response: BtcHeaderResponse = deps.querier.query_wasm_smart(&contract_addr, &msg)?;
    Ok(response)
}

/// Query the tip header from the BTC light client
pub fn query_tip_header(deps: Deps) -> Result<BtcHeaderResponse, ContractError> {
    let contract_addr = get_contract_addr(deps)?;
    let msg = btc_light_client::msg::contract::QueryMsg::BtcTipHeader {};
    let response: BtcHeaderResponse = deps.querier.query_wasm_smart(&contract_addr, &msg)?;
    Ok(response)
}

/// Query a header by height from the BTC light client
pub fn query_header(deps: Deps, height: u32) -> Result<BtcHeaderResponse, ContractError> {
    let contract_addr = get_contract_addr(deps)?;
    let msg = btc_light_client::msg::contract::QueryMsg::BtcHeader { height };
    let response: BtcHeaderResponse = deps.querier.query_wasm_smart(&contract_addr, &msg)?;
    Ok(response)
}

/// Query a header by hash from the BTC light client
pub fn query_header_by_hash(deps: Deps, hash: &str) -> Result<BtcHeaderResponse, ContractError> {
    let contract_addr = get_contract_addr(deps)?;
    let msg = btc_light_client::msg::contract::QueryMsg::BtcHeaderByHash {
        hash: hash.to_string(),
    };
    let response: BtcHeaderResponse = deps.querier.query_wasm_smart(&contract_addr, &msg)?;
    Ok(response)
}

/// Query headers with pagination from the BTC light client
pub fn query_headers(
    deps: Deps,
    start_after: Option<u32>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<BtcHeadersResponse, ContractError> {
    let contract_addr = get_contract_addr(deps)?;
    let msg = btc_light_client::msg::contract::QueryMsg::BtcHeaders {
        start_after,
        limit,
        reverse,
    };
    let response: BtcHeadersResponse = deps.querier.query_wasm_smart(&contract_addr, &msg)?;
    Ok(response)
}
