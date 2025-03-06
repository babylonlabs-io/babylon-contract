use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use cw2::set_contract_version;

use babylon_bindings::BabylonMsg;

use crate::error::ContractError;
use crate::msg::btc_header::BtcHeader;
use crate::msg::contract::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::btc_light_client::{
    handle_btc_headers_from_user, init_from_user, is_initialized,
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
        ExecuteMsg::BtcHeaders { headers } => handle_btc_headers(deps, headers),
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

fn handle_btc_headers(
    deps: DepsMut,
    headers: Vec<BtcHeader>,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Check if the BTC light client has been initialized
    if !is_initialized(deps.storage) {
        // Check if there are enough headers for initialization
        let cfg = CONFIG.load(deps.storage)?;
        if headers.len() < cfg.btc_confirmation_depth as usize {
            return Err(ContractError::InitErrorLength(cfg.btc_confirmation_depth));
        }

        init_from_user(deps.storage, &headers)?;
        Ok(Response::new().add_attribute("action", "init_btc_light_client"))
    } else {
        handle_btc_headers_from_user(deps.storage, &headers)?;
        Ok(Response::new().add_attribute("action", "update_btc_light_client"))
    }
}
