use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use cw2::set_contract_version;

use babylon_bindings::BabylonMsg;

use crate::error::ContractError;
use crate::msg::btc_header::BtcHeader;
use crate::msg::contract::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::btc_light_client::{
    get_tip, handle_btc_headers_from_babylon, init, is_initialized,
};
use crate::state::config::{Config, CONFIG};

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
    use crate::queries::btc_header::*;

    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&CONFIG.load(deps.storage)?)?),
        QueryMsg::BtcBaseHeader {} => Ok(to_json_binary(&btc_base_header(&deps)?)?),
        QueryMsg::BtcTipHeader {} => Ok(to_json_binary(&btc_tip_header(&deps)?)?),
        QueryMsg::BtcHeader { height } => Ok(to_json_binary(&btc_header(&deps, height)?)?),
        QueryMsg::BtcHeaderByHash { hash } => {
            Ok(to_json_binary(&btc_header_by_hash(&deps, &hash)?)?)
        }
        QueryMsg::BtcHeaders {
            start_after,
            limit,
            reverse,
        } => Ok(to_json_binary(&btc_headers(
            &deps,
            start_after,
            limit,
            reverse,
        )?)?),
    }
}

fn init_btc_light_client(
    deps: DepsMut,
    headers: Vec<crate::msg::btc_header::BtcHeader>,
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
    let mut prev_work = crate::utils::btc_light_client::zero_work();
    for (i, header) in headers.iter().enumerate() {
        let btc_header_info = header.to_btc_header_info(i as u32, prev_work)?;
        prev_work = crate::utils::btc_light_client::total_work(&btc_header_info)?;
        btc_headers.push(btc_header_info);
    }

    // Verify headers
    crate::utils::btc_light_client::verify_headers(
        &babylon_bitcoin::chain_params::get_chain_params(cfg.network),
        &btc_headers[0],
        &btc_headers[1..],
    )?;

    // Save headers
    init(deps.storage, &btc_headers)?;

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
    let mut prev_work = crate::utils::btc_light_client::total_work(&tip)?;
    for (i, header) in headers.iter().enumerate() {
        let btc_header_info = header.to_btc_header_info(tip.height + i as u32 + 1, prev_work)?;
        prev_work = crate::utils::btc_light_client::total_work(&btc_header_info)?;
        btc_headers.push(btc_header_info);
    }

    // Verify headers
    crate::utils::btc_light_client::verify_headers(
        &babylon_bitcoin::chain_params::get_chain_params(CONFIG.load(deps.storage)?.network),
        &tip,
        &btc_headers,
    )?;

    // Save headers
    handle_btc_headers_from_babylon(deps.storage, &btc_headers)?;

    Ok(Response::new().add_attribute("action", "update_btc_light_client"))
}
