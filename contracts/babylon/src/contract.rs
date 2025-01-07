use babylon_bindings::query::{get_babylon_sdk_params, BabylonQuery};
use cosmwasm_std::{
    to_json_binary, to_json_string, Addr, Binary, Deps, DepsMut, Empty, Env, IbcMsg, MessageInfo,
    QueryResponse, Response, SubMsg, SubMsgResponse, WasmMsg,
};
use cw2::set_contract_version;
use cw_utils::must_pay;

use babylon_apis::{btc_staking_api, finality_api, to_bech32_addr, to_module_canonical_addr};
use babylon_bindings::BabylonMsg;

use crate::error::ContractError;
use crate::ibc::{ibc_packet, packet_timeout, TransferInfo, IBC_CHANNEL, IBC_TRANSFER};
use crate::msg::contract::{ContractMsg, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries;
use crate::state::btc_light_client;
use crate::state::config::{Config, CONFIG};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    let denom = deps.querier.query_bonded_denom()?;
    let mut cfg = Config {
        network: msg.network.clone(),
        babylon_tag: msg.babylon_tag_to_bytes()?,
        btc_confirmation_depth: msg.btc_confirmation_depth,
        checkpoint_finalization_timeout: msg.checkpoint_finalization_timeout,
        notify_cosmos_zone: msg.notify_cosmos_zone,
        consumer_name: None,
        consumer_description: None,
        denom,
    };

    let res = Response::new().add_attribute("action", "instantiate");

    // Update config with consumer information
    cfg.consumer_name = msg.consumer_name;
    cfg.consumer_description = msg.consumer_description;

    // Save the config after potentially updating it
    CONFIG.save(deps.storage, &cfg)?;

    // Format and save the IBC transfer info
    if let Some(transfer_info) = msg.transfer_info {
        let (to_address, address_type) = match transfer_info.recipient {
            crate::msg::ibc::Recipient::ContractAddr(addr) => (addr, "contract"),
            crate::msg::ibc::Recipient::ModuleAddr(module) => (
                to_bech32_addr("bbn", &to_module_canonical_addr(&module))?.to_string(),
                "module",
            ),
        };
        IBC_TRANSFER.save(
            deps.storage,
            &TransferInfo {
                channel_id: transfer_info.channel_id,
                to_address,
                address_type: address_type.to_string(),
            },
        )?;
    }

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(res)
}

pub fn query(
    deps: Deps<BabylonQuery>,
    _env: Env,
    msg: QueryMsg,
) -> Result<QueryResponse, ContractError> {
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
        QueryMsg::TransferInfo {} => Ok(to_json_binary(&queries::transfer_info(deps)?)?),
    }
}

/// this is a no-op just to test how this integrates with wasmd
pub fn migrate(
    _deps: DepsMut<BabylonQuery>,
    _env: Env,
    _msg: Empty,
) -> Result<Response<BabylonMsg>, ContractError> {
    Ok(Response::default())
}

pub fn execute(
    deps: DepsMut<BabylonQuery>,
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
            // Check sender
            let params = get_babylon_sdk_params(&deps.querier)?;
            let btc_finality = params.btc_finality_contract_address;
            if info.sender != btc_finality {
                return Err(ContractError::Unauthorized {});
            }
            // Send to the staking contract for processing
            let mut res = Response::new();
            let btc_staking = params.btc_staking_contract_address;
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
        ExecuteMsg::SendRewards { fp_distribution } => {
            let cfg = CONFIG.load(deps.storage)?;
            // Assert the funds are there
            must_pay(&info, &cfg.denom)?;
            // Assert the sender is right
            let btc_finality = get_babylon_sdk_params(&deps.querier)?.btc_finality_contract_address;
            if info.sender != btc_finality {
                return Err(ContractError::Unauthorized {});
            }
            // Route to babylon over IBC, if available
            let transfer_info = IBC_TRANSFER.may_load(deps.storage)?;
            match transfer_info {
                Some(transfer_info) => {
                    // Build the payload
                    let payload_msg = to_json_string(&fp_distribution)?;
                    // Construct the transfer message
                    let ibc_msg = IbcMsg::Transfer {
                        channel_id: transfer_info.channel_id,
                        to_address: transfer_info.to_address,
                        amount: info.funds[0].clone(),
                        timeout: packet_timeout(&env),
                        memo: Some(payload_msg),
                    };

                    // Send packet only if we are IBC enabled
                    // TODO: send in test code when multi-test can handle it
                    #[cfg(not(any(test, feature = "library")))]
                    {
                        // TODO: Add events
                        Ok(Response::new().add_message(ibc_msg))
                    }
                    #[cfg(any(test, feature = "library"))]
                    {
                        let _ = ibc_msg;
                        Ok(Response::new())
                    }
                }
                None => {
                    // TODO: Send payload over the custom IBC channel for distribution
                    Ok(Response::new())
                }
            }
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
            admin: None,
            consumer_name: None,
            consumer_description: None,
            transfer_info: None,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn instantiate_finality_works() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            network: babylon_bitcoin::chain_params::Network::Regtest,
            babylon_tag: "01020304".to_string(),
            btc_confirmation_depth: 10,
            checkpoint_finalization_timeout: 100,
            notify_cosmos_zone: false,
            admin: None,
            consumer_name: None,
            consumer_description: None,
            transfer_info: None,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(1, res.messages.len());
        assert_eq!(
            res.messages[0].msg,
            WasmMsg::Instantiate {
                admin: None,
                code_id: 2,
                msg: Binary::from(b"{}"),
                funds: vec![],
                label: "BTC Finality".into(),
            }
            .into()
        );
    }

    #[test]
    fn instantiate_finality_params_works() {
        let mut deps = mock_dependencies();
        let params = r#"{"params": {"epoch_length": 10}}"#;
        let msg = InstantiateMsg {
            network: babylon_bitcoin::chain_params::Network::Regtest,
            babylon_tag: "01020304".to_string(),
            btc_confirmation_depth: 10,
            checkpoint_finalization_timeout: 100,
            notify_cosmos_zone: false,
            admin: None,
            consumer_name: None,
            consumer_description: None,
            transfer_info: None,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(1, res.messages.len());
        assert_eq!(
            res.messages[0].msg,
            WasmMsg::Instantiate {
                admin: None,
                code_id: 2,
                msg: Binary::from(params.as_bytes()),
                funds: vec![],
                label: "BTC Finality".into(),
            }
            .into()
        );
    }

    #[test]
    fn test_module_address() {
        // Example usage
        let prefix = "bbn";
        let module_name = "zoneconcierge";

        let addr = to_bech32_addr(prefix, &to_module_canonical_addr(module_name)).unwrap();
        assert_eq!(
            addr.to_string(),
            "bbn1wdptld6nw2plxzf0w62gqc60tlw5kypzej89y3"
        );
    }
}
