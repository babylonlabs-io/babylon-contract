use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use cw2::set_contract_version;

use babylon_bindings::BabylonMsg;
use babylon_bitcoin::{chain_params, BlockHash};

use crate::error::ContractError;
use crate::msg::btc_header::{BtcHeader, BtcHeaderResponse, BtcHeadersResponse};
use crate::msg::contract::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::btc_light_client::{
    get_base_header, get_header, get_header_by_hash, get_headers, get_tip, insert_headers,
    is_initialized, set_base_header, set_tip,
};
use crate::state::config::{Config, CONFIG};
use crate::utils::btc_light_client::{total_work, verify_headers, zero_work};
use std::str::FromStr;

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    msg.validate()?;

    // Initialize config
    let cfg = Config {
        network: msg.network,
        btc_confirmation_depth: msg.btc_confirmation_depth,
        checkpoint_finalization_timeout: msg.checkpoint_finalization_timeout,
    };
    CONFIG.save(deps.storage, &cfg)?;

    // Set contract version
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response<BabylonMsg>, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("action", "migrate"))
}

pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    match msg {
        ExecuteMsg::InitBtcLightClient { headers } => init_btc_light_client(deps, headers),
        ExecuteMsg::BtcHeaders { headers } => update_btc_light_client(deps, headers),
    }
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    let result = match msg {
        QueryMsg::BtcBaseHeader {} => {
            let header = get_base_header(deps.storage)?;
            to_json_binary(&BtcHeaderResponse::try_from(&header)?)?
        }
        QueryMsg::BtcTipHeader {} => {
            let header = get_tip(deps.storage)?;
            to_json_binary(&BtcHeaderResponse::try_from(&header)?)?
        }
        QueryMsg::BtcHeader { height } => {
            let header = get_header(deps.storage, height)?;
            to_json_binary(&BtcHeaderResponse::try_from(&header)?)?
        }
        QueryMsg::BtcHeaderByHash { hash } => {
            let hash = BlockHash::from_str(&hash).map_err(ContractError::HashError)?;
            let header = get_header_by_hash(deps.storage, hash.as_ref())?;
            to_json_binary(&BtcHeaderResponse::try_from(&header)?)?
        }
        QueryMsg::BtcHeaders {
            start_after,
            limit,
            reverse,
        } => {
            let headers = get_headers(deps.storage, start_after, limit, reverse)?;
            to_json_binary(&BtcHeadersResponse::try_from(headers)?)?
        }
    };
    Ok(result)
}

fn init_btc_light_client(
    deps: DepsMut,
    headers: Vec<BtcHeader>,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Check if the BTC light client has been initialized
    if is_initialized(deps.storage) {
        return Err(ContractError::InitError {});
    }

    // Check if there are enough headers
    let cfg = CONFIG.load(deps.storage)?;
    if headers.len() < cfg.btc_confirmation_depth as usize {
        return Err(ContractError::InitErrorLength(cfg.btc_confirmation_depth));
    }

    // Convert headers to BtcHeaderInfo
    let mut btc_headers = Vec::with_capacity(headers.len());
    let mut prev_work = zero_work();
    for (i, header) in headers.iter().enumerate() {
        let btc_header_info = header.to_btc_header_info(i as u32, prev_work)?;
        prev_work = total_work(&btc_header_info)?;
        btc_headers.push(btc_header_info);
    }

    // Verify headers
    verify_headers(
        &chain_params::get_chain_params(cfg.network),
        &btc_headers[0],
        &btc_headers[1..],
    )?;

    // Save headers
    insert_headers(deps.storage, &btc_headers)?;

    // Save base header and tip
    set_base_header(deps.storage, &btc_headers[0])?;
    set_tip(deps.storage, btc_headers.last().unwrap())?;

    Ok(Response::new().add_attribute("action", "init_btc_light_client"))
}

fn update_btc_light_client(
    deps: DepsMut,
    headers: Vec<BtcHeader>,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Check if the BTC light client has been initialized
    if !is_initialized(deps.storage) {
        return Err(ContractError::InitError {});
    }

    // Get the current tip
    let tip = get_tip(deps.storage)?;

    // Convert headers to BtcHeaderInfo
    let mut btc_headers = Vec::with_capacity(headers.len());
    let mut prev_work = total_work(&tip)?;
    for (i, header) in headers.iter().enumerate() {
        let btc_header_info = header.to_btc_header_info(tip.height + i as u32 + 1, prev_work)?;
        prev_work = total_work(&btc_header_info)?;
        btc_headers.push(btc_header_info);
    }

    // Verify headers
    verify_headers(
        &chain_params::get_chain_params(CONFIG.load(deps.storage)?.network),
        &tip,
        &btc_headers,
    )?;

    // Save headers
    insert_headers(deps.storage, &btc_headers)?;

    // Update tip
    set_tip(deps.storage, btc_headers.last().unwrap())?;

    Ok(Response::new().add_attribute("action", "update_btc_light_client"))
}
