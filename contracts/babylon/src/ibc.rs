use crate::error::ContractError;
use babylon_bindings::BabylonMsg;
use babylon_proto::babylon::zoneconcierge::v1::{
    zoneconcierge_packet_data::Packet, BtcTimestamp, ConsumerRegisterIbcPacket,
    ZoneconciergePacketData,
};

use crate::state::config::CONFIG;
use cosmwasm_std::{
    Binary, DepsMut, Env, Event, Ibc3ChannelOpenResponse, IbcBasicResponse, IbcChannel,
    IbcChannelCloseMsg, IbcChannelConnectMsg, IbcChannelOpenMsg, IbcChannelOpenResponse, IbcMsg,
    IbcOrder, IbcPacketAckMsg, IbcPacketReceiveMsg, IbcPacketTimeoutMsg, IbcReceiveResponse,
    IbcTimeout, Never, StdAck, StdError, StdResult,
};
use cw_storage_plus::Item;
use prost::Message;

pub const IBC_VERSION: &str = "zoneconcierge-1";
pub const IBC_ORDERING: IbcOrder = IbcOrder::Ordered;

// IBC specific state
pub const IBC_CHANNEL: Item<IbcChannel> = Item::new("ibc_channel");

/// This is executed during the ChannelOpenInit and ChannelOpenTry
/// of the IBC 4-step channel protocol
/// (see https://github.com/cosmos/ibc/tree/main/spec/core/ics-004-channel-and-packet-semantics#channel-lifecycle-management)
/// In the case of ChannelOpenTry there's a counterparty_version attribute in the message.
/// Here we ensure the ordering and version constraints.
pub fn ibc_channel_open(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, ContractError> {
    // Ensure we have no channel yet
    if IBC_CHANNEL.may_load(deps.storage)?.is_some() {
        return Err(ContractError::IbcChannelAlreadyOpen {});
    }
    // The IBC channel has to be ordered
    let channel = msg.channel();
    if channel.order != IBC_ORDERING {
        return Err(ContractError::IbcUnorderedChannel {});
    }

    // In IBCv3 we don't check the version string passed in the message
    // and only check the counterparty version
    if let Some(counter_version) = msg.counterparty_version() {
        if counter_version != IBC_VERSION {
            return Err(ContractError::IbcInvalidCounterPartyVersion {
                version: IBC_VERSION.to_string(),
            });
        }
    }

    // We return the version we need (which could be different from the counterparty version)
    Ok(Some(Ibc3ChannelOpenResponse {
        version: IBC_VERSION.to_string(),
    }))
}

/// Second part of the 4-step handshake, i.e. ChannelOpenAck and ChannelOpenConfirm.
pub fn ibc_channel_connect(
    deps: DepsMut,
    env: Env,
    msg: IbcChannelConnectMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // Ensure we have no channel yet
    if IBC_CHANNEL.may_load(deps.storage)?.is_some() {
        return Err(ContractError::IbcChannelAlreadyOpen {});
    }
    let channel = msg.channel();

    // Store the channel
    IBC_CHANNEL.save(deps.storage, channel)?;

    // Load the config
    let cfg = CONFIG.load(deps.storage)?;

    let chan_id = &channel.endpoint.channel_id;
    let mut response = IbcBasicResponse::new()
        .add_attribute("action", "ibc_connect")
        .add_attribute("channel_id", chan_id)
        .add_event(Event::new("ibc").add_attribute("channel", "connect"));

    // If the consumer name and description are set, create and send a ConsumerRegister packet
    if let (Some(name), Some(description)) = (&cfg.consumer_name, &cfg.consumer_description) {
        let consumer_register_packet = ConsumerRegisterIbcPacket {
            consumer_name: name.clone(),
            consumer_description: description.clone(),
        };

        let packet_data = ZoneconciergePacketData {
            packet: Some(Packet::ConsumerRegister(consumer_register_packet)),
        };

        let ibc_msg = IbcMsg::SendPacket {
            channel_id: channel.endpoint.channel_id.clone(),
            data: Binary::new(packet_data.encode_to_vec()),
            timeout: packet_timeout(&env),
        };

        response = response
            .add_message(ibc_msg)
            .add_attribute("consumer_name", name)
            .add_attribute("consumer_description", description);
    }

    Ok(response)
}

/// This is invoked on the IBC Channel Close message
/// We perform any cleanup related to the channel
pub fn ibc_channel_close(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelCloseMsg,
) -> StdResult<IbcBasicResponse> {
    let channel = msg.channel();
    // Get contract address and remove lookup
    let channel_id = channel.endpoint.channel_id.as_str();

    Ok(IbcBasicResponse::new()
        .add_attribute("action", "ibc_close")
        .add_attribute("channel_id", channel_id))

    // TODO: erase all contract state upon closing the channel
}

/// Invoked when an IBC packet is received
/// We decode the contents of the packet and if it matches one of the packets we support
/// execute the relevant function, otherwise return an error.
/// NOTE: In its current form, this method does not modify state.
/// If we want to modify state here, we have to follow the techniques outlined here:
/// https://github.com/CosmWasm/cosmwasm/blob/main/IBC.md#acknowledging-errors
/// That's because we want to send an ACK for the packet regardless if there's an error or not,
/// but in the case of an error, we do not want the state to be committed.
pub fn ibc_packet_receive(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse<BabylonMsg>, Never> {
    // put this in a closure so we can convert all error responses into acknowledgements
    (|| {
        let packet = msg.packet;
        // which local channel did this packet come on
        let caller = packet.dest.channel_id;
        let zc_packet_data =
            ZoneconciergePacketData::decode(packet.data.as_slice()).map_err(|e| {
                StdError::generic_err(format!("failed to decode ZoneconciergePacketData: {e}"))
            })?;
        let zc_packet = zc_packet_data
            .packet
            .ok_or(StdError::generic_err("empty IBC packet"))?;
        match zc_packet {
            Packet::BtcTimestamp(btc_ts) => ibc_packet::handle_btc_timestamp(deps, caller, &btc_ts),
            Packet::BtcStaking(btc_staking) => {
                ibc_packet::handle_btc_staking(deps, caller, &btc_staking)
            }
            Packet::ConsumerRegister(_) => Err(StdError::generic_err(
                "ConsumerRegister packet should not be received",
            )),
            Packet::ConsumerSlashing(_) => Err(StdError::generic_err(
                "ConsumerSlashing packet should not be received",
            )),
        }
    })()
    .or_else(|e| {
        // we try to capture all app-level errors and convert them into
        // acknowledgement packets that contain an error code.
        Ok(
            IbcReceiveResponse::new(StdAck::error(format!("invalid packet: {e}"))) // TODO: design error ack format
                .add_event(Event::new("ibc").add_attribute("packet", "receive")),
        )
    })
}

// Methods to handle PacketMsg variants
pub(crate) mod ibc_packet {
    use super::*;
    use crate::state::config::CONFIG;
    use babylon_apis::btc_staking_api::SlashedBtcDelegation;
    use babylon_apis::btc_staking_api::{
        ActiveBtcDelegation, BtcUndelegationInfo, CovenantAdaptorSignatures,
        FinalityProviderDescription, NewFinalityProvider, ProofOfPossessionBtc, SignatureInfo,
        UnbondedBtcDelegation,
    };
    use babylon_apis::finality_api::Evidence;
    use babylon_proto::babylon::btcstaking::v1::BtcStakingIbcPacket;
    use babylon_proto::babylon::zoneconcierge::v1::zoneconcierge_packet_data::Packet::ConsumerSlashing;
    use babylon_proto::babylon::zoneconcierge::v1::ConsumerSlashingIbcPacket;
    use cosmwasm_std::{to_json_binary, Decimal, IbcChannel, IbcMsg, WasmMsg};
    use std::str::FromStr;

    pub fn handle_btc_timestamp(
        deps: DepsMut,
        _caller: String,
        btc_ts: &BtcTimestamp,
    ) -> StdResult<IbcReceiveResponse<BabylonMsg>> {
        let storage = deps.storage;
        let cfg = CONFIG.load(storage)?;

        // handle the BTC timestamp, i.e., verify the BTC timestamp and update the contract state
        let msg_option = crate::state::handle_btc_timestamp(storage, btc_ts)?;

        // construct response
        let mut resp: IbcReceiveResponse<BabylonMsg> =
            IbcReceiveResponse::new(StdAck::success(vec![])); // TODO: design response format
                                                              // add attribute to response
        resp = resp.add_attribute("action", "receive_btc_timestamp");

        // if the BTC timestamp carries a Babylon message for the Cosmos zone, and
        // the contract enables sending messages to the Cosmos zone, then
        // add this message to response
        if let Some(msg) = msg_option {
            if cfg.notify_cosmos_zone {
                resp = resp.add_message(msg);
            }
        }

        Ok(resp)
    }

    pub fn handle_btc_staking(
        deps: DepsMut,
        _caller: String,
        btc_staking: &BtcStakingIbcPacket,
    ) -> StdResult<IbcReceiveResponse<BabylonMsg>> {
        let storage = deps.storage;
        let cfg = CONFIG.load(storage)?;

        // Route the packet to the btc-staking contract
        let btc_staking_addr = cfg
            .btc_staking
            .ok_or(StdError::generic_err("btc_staking contract not set"))?;

        // Build the message to send to the BTC staking contract
        let msg = babylon_apis::btc_staking_api::ExecuteMsg::BtcStaking {
            new_fp: btc_staking
                .new_fp
                .iter()
                .map(|fp| {
                    Ok(NewFinalityProvider {
                        description: fp
                            .description
                            .as_ref()
                            .map(|d| FinalityProviderDescription {
                                moniker: d.moniker.clone(),
                                identity: d.identity.clone(),
                                website: d.website.clone(),
                                security_contact: d.security_contact.clone(),
                                details: d.details.clone(),
                            }),
                        commission: Decimal::from_str(&fp.commission)?,
                        addr: fp.addr.clone(),
                        btc_pk_hex: fp.btc_pk_hex.clone(),
                        pop: fp.pop.as_ref().map(|pop| ProofOfPossessionBtc {
                            btc_sig_type: pop.btc_sig_type,
                            btc_sig: pop.btc_sig.to_vec().into(),
                        }),
                        consumer_id: fp.consumer_id.clone(),
                    })
                })
                .collect::<StdResult<_>>()?,
            active_del: btc_staking
                .active_del
                .iter()
                .map(|d| {
                    Ok(ActiveBtcDelegation {
                        staker_addr: d.staker_addr.clone(),
                        btc_pk_hex: d.btc_pk_hex.clone(),
                        fp_btc_pk_list: d.fp_btc_pk_list.clone(),
                        start_height: d.start_height,
                        end_height: d.end_height,
                        total_sat: d.total_sat,
                        staking_tx: d.staking_tx.to_vec().into(),
                        slashing_tx: d.slashing_tx.to_vec().into(),
                        delegator_slashing_sig: d.delegator_slashing_sig.to_vec().into(),
                        covenant_sigs: d
                            .covenant_sigs
                            .iter()
                            .map(|s| CovenantAdaptorSignatures {
                                cov_pk: s.cov_pk.to_vec().into(),
                                adaptor_sigs: s
                                    .adaptor_sigs
                                    .iter()
                                    .map(|a| a.to_vec().into())
                                    .collect(),
                            })
                            .collect(),
                        staking_output_idx: d.staking_output_idx,
                        unbonding_time: d.unbonding_time,
                        undelegation_info: d
                            .undelegation_info
                            .as_ref()
                            .map(|ui| BtcUndelegationInfo {
                                unbonding_tx: ui.unbonding_tx.to_vec().into(),
                                delegator_unbonding_sig: ui.delegator_unbonding_sig.to_vec().into(),
                                covenant_unbonding_sig_list: ui
                                    .covenant_unbonding_sig_list
                                    .iter()
                                    .map(|s| SignatureInfo {
                                        pk: s.pk.to_vec().into(),
                                        sig: s.sig.to_vec().into(),
                                    })
                                    .collect(),
                                slashing_tx: ui.slashing_tx.to_vec().into(),
                                delegator_slashing_sig: ui.delegator_slashing_sig.to_vec().into(),
                                covenant_slashing_sigs: ui
                                    .covenant_slashing_sigs
                                    .iter()
                                    .map(|s| CovenantAdaptorSignatures {
                                        cov_pk: s.cov_pk.to_vec().into(),
                                        adaptor_sigs: s
                                            .adaptor_sigs
                                            .iter()
                                            .map(|a| a.to_vec().into())
                                            .collect(),
                                    })
                                    .collect(),
                            })
                            .ok_or(StdError::generic_err("undelegation info not set"))?,
                        params_version: d.params_version,
                    })
                })
                .collect::<StdResult<_>>()?,
            slashed_del: btc_staking
                .slashed_del
                .iter()
                .map(|d| SlashedBtcDelegation {
                    staking_tx_hash: d.staking_tx_hash.clone(),
                    recovered_fp_btc_sk: d.recovered_fp_btc_sk.clone(),
                })
                .collect(),
            unbonded_del: btc_staking
                .unbonded_del
                .iter()
                .map(|u| UnbondedBtcDelegation {
                    staking_tx_hash: u.staking_tx_hash.clone(),
                    unbonding_tx_sig: u.unbonding_tx_sig.to_vec().into(),
                })
                .collect(),
        };

        let wasm_msg = WasmMsg::Execute {
            contract_addr: btc_staking_addr.to_string(),
            msg: to_json_binary(&msg)?,
            funds: vec![],
        };

        // construct response
        let mut resp: IbcReceiveResponse<BabylonMsg> =
            IbcReceiveResponse::new(StdAck::success(vec![])); // TODO: design response format
                                                              // add wasm message to response
        resp = resp.add_message(wasm_msg);
        // add attribute to response
        resp = resp.add_attribute("action", "receive_btc_staking");

        Ok(resp)
    }

    pub fn slashing_msg(
        env: &Env,
        channel: &IbcChannel,
        evidence: &Evidence,
        secret_key: &[u8],
    ) -> Result<IbcMsg, ContractError> {
        let packet = ZoneconciergePacketData {
            packet: Some(ConsumerSlashing(ConsumerSlashingIbcPacket {
                evidence: Some(babylon_proto::babylon::finality::v1::Evidence {
                    fp_btc_pk: evidence.fp_btc_pk.to_vec().into(),
                    block_height: evidence.block_height,
                    pub_rand: evidence.pub_rand.to_vec().into(),
                    canonical_app_hash: evidence.canonical_app_hash.to_vec().into(),
                    fork_app_hash: evidence.fork_app_hash.to_vec().into(),
                    canonical_finality_sig: evidence.canonical_finality_sig.to_vec().into(),
                    fork_finality_sig: evidence.fork_finality_sig.to_vec().into(),
                }),
                secret_key: secret_key.to_vec().into(),
            })),
        };
        let msg = IbcMsg::SendPacket {
            channel_id: channel.endpoint.channel_id.clone(),
            data: Binary::new(packet.encode_to_vec()),
            timeout: packet_timeout(env),
        };
        Ok(msg)
    }
}

const DEFAULT_TIMEOUT: u64 = 10 * 60;

pub fn packet_timeout(env: &Env) -> IbcTimeout {
    let timeout = env.block.time.plus_seconds(DEFAULT_TIMEOUT);
    IbcTimeout::with_timestamp(timeout)
}

pub fn ibc_packet_ack(
    _deps: DepsMut,
    _env: Env,
    _msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    Ok(IbcBasicResponse::default())
}

pub fn ibc_packet_timeout(
    _deps: DepsMut,
    _env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // TODO: handle the timeout / error
    Err(ContractError::IbcTimeout(
        msg.packet.dest.channel_id,
        msg.packet.dest.port_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::instantiate;
    use crate::msg::contract::InstantiateMsg;
    use cosmwasm_std::testing::message_info;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_ibc_channel_open_try, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::OwnedDeps;

    const CREATOR: &str = "creator";

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
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
            consumer_name: None,
            consumer_description: None,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
        deps
    }

    #[test]
    fn enforce_version_in_handshake() {
        let mut deps = setup();

        let wrong_order = mock_ibc_channel_open_try("channel-12", IbcOrder::Unordered, IBC_VERSION);
        ibc_channel_open(deps.as_mut(), mock_env(), wrong_order).unwrap_err();

        let wrong_version = mock_ibc_channel_open_try("channel-12", IbcOrder::Ordered, "reflect");
        ibc_channel_open(deps.as_mut(), mock_env(), wrong_version).unwrap_err();

        let valid_handshake = mock_ibc_channel_open_try("channel-12", IBC_ORDERING, IBC_VERSION);
        ibc_channel_open(deps.as_mut(), mock_env(), valid_handshake).unwrap();
    }
}
