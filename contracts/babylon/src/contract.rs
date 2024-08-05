use crate::error::ContractError;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Deps, DepsMut, Empty, Env, MessageInfo, QueryResponse, Reply,
    Response, SubMsg, SubMsgResponse, WasmMsg,
};
use cw_utils::ParseReplyError;

use crate::ibc::{ibc_packet, IBC_CHANNEL};
use crate::msg::contract::{ContractMsg, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries;
use crate::state::btc_light_client;
use crate::state::config::{Config, CONFIG};
use babylon_bindings::BabylonMsg;

const REPLY_ID_INSTANTIATE: u64 = 1;

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

    // initialise config
    let cfg = Config {
        network: msg.network.clone(),
        babylon_tag: msg.babylon_tag_to_bytes()?,
        btc_confirmation_depth: msg.btc_confirmation_depth,
        checkpoint_finalization_timeout: msg.checkpoint_finalization_timeout,
        notify_cosmos_zone: msg.notify_cosmos_zone,
        btc_staking: None, // Will be set in `reply` if `btc_staking_code_id` is provided
    };
    CONFIG.save(deps.storage, &cfg)?;

    let mut res = Response::new().add_attribute("action", "instantiate");

    if let Some(btc_staking_code_id) = msg.btc_staking_code_id {
        // Instantiate BTC staking contract
        let init_msg = WasmMsg::Instantiate {
            admin: msg.admin,
            code_id: btc_staking_code_id,
            msg: msg.btc_staking_msg.unwrap_or(Binary::from(b"{}")),
            funds: vec![],
            label: "BTC Staking".into(),
        };
        let init_msg = SubMsg::reply_on_success(init_msg, REPLY_ID_INSTANTIATE);

        res = res.add_submessage(init_msg);
    }
    Ok(res)
}

pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response<BabylonMsg>, ContractError> {
    match reply.id {
        REPLY_ID_INSTANTIATE => reply_init_callback(deps, reply.result.unwrap()),
        _ => Err(ContractError::InvalidReplyId(reply.id)),
    }
}

/// Store virtual BTC staking address
fn reply_init_callback(
    deps: DepsMut,
    reply: SubMsgResponse,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Try to get contract address from events in reply
    for event in reply.events {
        if event.ty == "instantiate" {
            for attr in event.attributes {
                if attr.key == "_contract_address" {
                    let btc_staking = Addr::unchecked(attr.value);
                    CONFIG.update(deps.storage, |mut cfg| {
                        cfg.btc_staking = Some(btc_staking.clone());
                        Ok::<_, ContractError>(cfg)
                    })?;
                    return Ok(Response::new());
                }
            }
        }
    }
    // Fall back to deprecated way of getting contract address from data
    // TODO: Remove this if the method above works
    // TODO: Use the new `msg_responses` field if / when available
    // let init_data = parse_instantiate_response_data(&reply.data.unwrap())?;
    // let btc_staking = Addr::unchecked(init_data.contract_address);
    // CONFIG.update(deps.storage, |mut cfg| {
    //     cfg.btc_staking = Some(btc_staking.clone());
    //     Ok::<_, ContractError>(cfg)
    // })?;
    // Ok(Response::new())
    Err(ContractError::ParseReply(ParseReplyError::ParseFailure(
        "Cannot parse contract address".to_string(),
    )))
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
        ExecuteMsg::Slashing { fp_btc_pk, block_height, secret_key } => {
            // This is an internal routing message from the `btc-staking` contract
            // Check sender
            let btc_staking = CONFIG
                .load(deps.storage)?
                .btc_staking
                .ok_or(ContractError::BtcStakingNotSet {})?;
            if info.sender != btc_staking {
                return Err(ContractError::Unauthorized {});
            }
            // Send over IBC to the Provider (Babylon)
            let channel = IBC_CHANNEL.load(deps.storage)?;
            let msg = ibc_packet::slashing_msg(&env, &channel, &fp_btc_pk, block_height, &secret_key)?;
            // TODO: Add events
            Ok(Response::new().add_message(msg))
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
            admin: None,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }
}
