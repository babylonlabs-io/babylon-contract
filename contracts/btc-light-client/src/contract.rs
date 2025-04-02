use babylon_bitcoin::Work;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use cw2::set_contract_version;

use babylon_bindings::BabylonMsg;

use crate::error::ContractError;
use crate::msg::btc_header::BtcHeader;
use crate::msg::contract::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::btc_light_client::{handle_btc_headers_from_user, init, is_initialized};
use crate::state::config::{Config, CONFIG};
use crate::utils::btc_light_client::total_work;

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
        ExecuteMsg::BtcHeaders {
            headers,
            first_work,
            first_height,
        } => {
            let api = deps.api;
            let headers_len = headers.len();
            let resp = match handle_btc_headers(deps, headers, first_work, first_height) {
                Ok(resp) => {
                    api.debug(&format!("Successfully handled {} BTC headers", headers_len));
                    resp
                }
                Err(e) => {
                    let err = format!("Failed to handle {} BTC headers: {}", headers_len, e);
                    api.debug(&err);
                    return Err(e);
                }
            };

            Ok(resp)
        }
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
    first_work: Option<String>,
    first_height: Option<u32>,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Check if the BTC light client has been initialized
    if !is_initialized(deps.storage) {
        // Check if base work and height are provided
        if first_work.is_none() || first_height.is_none() {
            return Err(ContractError::InitError {
                msg: "base work or height is not provided".to_string(),
            });
        }

        // Check if there are enough headers for initialization
        let cfg = CONFIG.load(deps.storage)?;
        if headers.len() < cfg.btc_confirmation_depth as usize {
            return Err(ContractError::InitErrorLength(cfg.btc_confirmation_depth));
        }

        let first_work_hex = first_work.unwrap();
        let first_work_bytes = hex::decode(first_work_hex)?;
        let first_work = total_work(&first_work_bytes)?;

        init(deps.storage, &headers, &first_work, first_height.unwrap())?;
        Ok(Response::new().add_attribute("action", "init_btc_light_client"))
    } else {
        handle_btc_headers_from_user(deps.storage, &headers)?;
        Ok(Response::new().add_attribute("action", "update_btc_light_client"))
    }
}
