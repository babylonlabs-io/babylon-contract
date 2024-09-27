use cosmwasm_std::{
    to_json_binary, Addr, Binary, Deps, DepsMut, Empty, Env, MessageInfo, QueryResponse, Reply,
    Response, SubMsg, SubMsgResponse, WasmMsg,
};
use cw2::set_contract_version;
use cw_utils::ParseReplyError;

use babylon_apis::{btc_staking_api, finality_api};
use babylon_bindings::BabylonMsg;

use crate::error::ContractError;
use crate::ibc::{ibc_packet, IBC_CHANNEL};
use crate::msg::contract::{ContractMsg, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries;
use crate::state::btc_light_client;
use crate::state::config::{Config, CONFIG};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

const REPLY_ID_INSTANTIATE_STAKING: u64 = 2;
const REPLY_ID_INSTANTIATE_FINALITY: u64 = 3;

/// When we instantiate the Babylon contract, it will optionally instantiate a BTC staking
/// contract – if its code id is provided – to work with it for BTC re-staking support,
/// as they both need references to each other.
/// The admin of the BTC staking contract is taken as an explicit argument.
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    msg.validate()?;

    // Initialize config with None values for consumer fields
    let mut cfg = Config {
        network: msg.network.clone(),
        babylon_tag: msg.babylon_tag_to_bytes()?,
        btc_confirmation_depth: msg.btc_confirmation_depth,
        checkpoint_finalization_timeout: msg.checkpoint_finalization_timeout,
        notify_cosmos_zone: msg.notify_cosmos_zone,
        btc_staking: None, // Will be set in `reply` if `btc_staking_code_id` is provided
        btc_finality: None, // Will be set in `reply` if `btc_finality_code_id` is provided
        consumer_name: None,
        consumer_description: None,
    };

    let mut res = Response::new().add_attribute("action", "instantiate");

    if let Some(btc_staking_code_id) = msg.btc_staking_code_id {
        // Update config with consumer information
        cfg.consumer_name = msg.consumer_name;
        cfg.consumer_description = msg.consumer_description;

        // Instantiate BTC staking contract
        let init_msg = WasmMsg::Instantiate {
            admin: msg.admin.clone(),
            code_id: btc_staking_code_id,
            msg: msg.btc_staking_msg.unwrap_or(Binary::from(b"{}")),
            funds: vec![],
            label: "BTC Staking".into(),
        };
        let init_msg = SubMsg::reply_on_success(init_msg, REPLY_ID_INSTANTIATE_STAKING);

        // Test code sets a channel, so that we can better approximate IBC in test code
        #[cfg(any(test, all(feature = "library", not(target_arch = "wasm32"))))]
        {
            let channel = cosmwasm_std::testing::mock_ibc_channel(
                "channel-123",
                cosmwasm_std::IbcOrder::Ordered,
                "babylon",
            );
            IBC_CHANNEL.save(deps.storage, &channel)?;
        }

        res = res.add_submessage(init_msg);
    }

    if let Some(btc_finality_code_id) = msg.btc_finality_code_id {
        // Instantiate BTC finality contract
        let init_msg = WasmMsg::Instantiate {
            admin: msg.admin,
            code_id: btc_finality_code_id,
            msg: msg.btc_finality_msg.unwrap_or(Binary::from(b"{}")),
            funds: vec![],
            label: "BTC Finality".into(),
        };
        let init_msg = SubMsg::reply_on_success(init_msg, REPLY_ID_INSTANTIATE_FINALITY);

        res = res.add_submessage(init_msg);
    }

    // Save the config after potentially updating it
    CONFIG.save(deps.storage, &cfg)?;

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(res)
}

pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response<BabylonMsg>, ContractError> {
    match reply.id {
        REPLY_ID_INSTANTIATE_STAKING => reply_init_callback_staking(deps, reply.result.unwrap()),
        REPLY_ID_INSTANTIATE_FINALITY => reply_init_finality_callback(deps, reply.result.unwrap()),
        _ => Err(ContractError::InvalidReplyId(reply.id)),
    }
}

/// Tries to get contract address from events in reply
fn reply_init_get_contract_address(reply: SubMsgResponse) -> Result<Addr, ContractError> {
    for event in reply.events {
        if event.ty == "instantiate" {
            for attr in event.attributes {
                if attr.key == "_contract_address" {
                    return Ok(Addr::unchecked(attr.value));
                }
            }
        }
    }
    Err(ContractError::ParseReply(ParseReplyError::ParseFailure(
        "Cannot parse contract address".to_string(),
    )))
}

/// Store BTC staking address
fn reply_init_callback_staking(
    deps: DepsMut,
    reply: SubMsgResponse,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Try to get contract address from events in reply
    let addr = reply_init_get_contract_address(reply)?;
    CONFIG.update(deps.storage, |mut cfg| {
        cfg.btc_staking = Some(addr);
        Ok::<_, ContractError>(cfg)
    })?;
    Ok(Response::new())
}

/// Store BTC finality address
fn reply_init_finality_callback(
    deps: DepsMut,
    reply: SubMsgResponse,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Try to get contract address from events in reply
    let finality_addr = reply_init_get_contract_address(reply)?;
    CONFIG.update(deps.storage, |mut cfg| {
        cfg.btc_finality = Some(finality_addr.clone());
        Ok::<_, ContractError>(cfg)
    })?;
    // Set the BTC staking contract address to the BTC finality contract
    let cfg = CONFIG.load(deps.storage)?;
    let msg = finality_api::ExecuteMsg::UpdateStaking {
        staking: cfg
            .btc_staking
            .ok_or(ContractError::BtcStakingNotSet {})?
            .to_string(),
    };
    let wasm_msg = WasmMsg::Execute {
        contract_addr: finality_addr.to_string(),
        msg: to_json_binary(&msg)?,
        funds: vec![],
    };
    Ok(Response::new().add_message(wasm_msg))
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<QueryResponse, ContractError> {
    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&queries::config(deps)?)?),
        QueryMsg::BtcBaseHeader {} => Ok(to_json_binary(&queries::btc_base_header(deps)?)?),
        QueryMsg::BtcTipHeader {} => Ok(to_json_binary(&queries::btc_tip_header(deps)?)?),
        QueryMsg::BtcHeader { height } => Ok(to_json_binary(&queries::btc_header(deps, height)?)?),
        QueryMsg::BtcHeaderByHash { hash } => {
            Ok(to_json_binary(&queries::btc_header_by_hash(deps, &hash)?)?)
        }
        QueryMsg::BtcHeaders {
            start_after,
            limit,
            reverse,
        } => Ok(to_json_binary(&queries::btc_headers(
            deps,
            start_after,
            limit,
            reverse,
        )?)?),
        QueryMsg::BabylonBaseEpoch {} => Ok(to_json_binary(&queries::babylon_base_epoch(deps)?)?),
        QueryMsg::BabylonLastEpoch {} => Ok(to_json_binary(&queries::babylon_last_epoch(deps)?)?),
        QueryMsg::BabylonEpoch { epoch_number } => Ok(to_json_binary(&queries::babylon_epoch(
            deps,
            epoch_number,
        )?)?),
        QueryMsg::BabylonCheckpoint { epoch_number } => Ok(to_json_binary(
            &queries::babylon_checkpoint(deps, epoch_number)?,
        )?),
        QueryMsg::CzLastHeader {} => Ok(to_json_binary(&queries::cz_last_header(deps)?)?),
        QueryMsg::CzHeader { height } => Ok(to_json_binary(&queries::cz_header(deps, height)?)?),
    }
}

/// this is a no-op just to test how this integrates with wasmd
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response<BabylonMsg>, ContractError> {
    Ok(Response::default())
}

pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    match msg {
        ExecuteMsg::BtcHeaders {
            headers: btc_headers,
        } => {
            if btc_light_client::is_initialized(deps.storage) {
                btc_light_client::handle_btc_headers_from_user(deps.storage, &btc_headers)?;
            } else {
                btc_light_client::init_from_user(deps.storage, &btc_headers)?;
            }
            // TODO: Add events
            Ok(Response::new())
        }
        ExecuteMsg::Slashing { evidence } => {
            // This is an internal routing message from the `btc_finality` contract
            let cfg = CONFIG.load(deps.storage)?;
            // Check sender
            let btc_finality = cfg
                .btc_finality
                .ok_or(ContractError::BtcFinalityNotSet {})?;
            if info.sender != btc_finality {
                return Err(ContractError::Unauthorized {});
            }
            // Send to the staking contract for processing
            let mut res = Response::new();
            let btc_staking = cfg.btc_staking.ok_or(ContractError::BtcStakingNotSet {})?;
            // Slashes this finality provider, i.e., sets its slashing height to the block height
            // and its power to zero
            let msg = btc_staking_api::ExecuteMsg::Slash {
                fp_btc_pk_hex: hex::encode(evidence.fp_btc_pk.clone()),
            };
            let wasm_msg = WasmMsg::Execute {
                contract_addr: btc_staking.to_string(),
                msg: to_json_binary(&msg)?,
                funds: vec![],
            };
            res = res.add_message(wasm_msg);

            // Send over IBC to the Provider (Babylon)
            let channel = IBC_CHANNEL.load(deps.storage)?;
            let ibc_msg = ibc_packet::slashing_msg(&env, &channel, &evidence)?;
            // Send packet only if we are IBC enabled
            // TODO: send in test code when multi-test can handle it
            #[cfg(not(any(test, feature = "library")))]
            {
                res = res.add_message(ibc_msg);
            }
            #[cfg(any(test, feature = "library"))]
            {
                let _ = ibc_msg;
            }

            // TODO: Add events
            Ok(res)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use babylon_bitcoin::BlockHeader;
    use cosmwasm_std::testing::message_info;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};

    const CREATOR: &str = "creator";

    #[test]
    fn test_deserialize_btc_header() {
        // https://babylon.explorers.guru/transaction/8CEC6D605A39378F560C2134ABC931AE7DED0D055A6655B82CC5A31D5DA0BE26
        let btc_header_hex = "00400720b2559c9eb13821d6df53ffab9ddf3a645c559f030cac050000000000000000001ff22ffaa13c41df6aebc4b9b09faf328748c3a45772b6a4c4da319119fd5be3b53a1964817606174cc4c4b0";
        let btc_header_bytes = hex::decode(btc_header_hex).unwrap();
        let _btc_header: BlockHeader = babylon_bitcoin::deserialize(&btc_header_bytes).unwrap();
    }

    #[test]
    fn instantiate_works() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            network: babylon_bitcoin::chain_params::Network::Regtest,
            babylon_tag: "01020304".to_string(),
            btc_confirmation_depth: 10,
            checkpoint_finalization_timeout: 100,
            notify_cosmos_zone: false,
            btc_staking_code_id: None,
            btc_staking_msg: None,
            btc_finality_code_id: None,
            btc_finality_msg: None,
            admin: None,
            consumer_name: None,
            consumer_description: None,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }
}
