use crate::error::ContractError;
use babylon_proto::babylon::zoneconcierge::v1::ZoneconciergePacketData;

use crate::state::config::CONFIG;
use cosmwasm_std::{
    Binary, DepsMut, Env, Event, Ibc3ChannelOpenResponse, IbcBasicResponse, IbcChannel,
    IbcChannelCloseMsg, IbcChannelConnectMsg, IbcChannelOpenMsg, IbcChannelOpenResponse, IbcOrder,
    IbcPacketAckMsg, IbcPacketTimeoutMsg, IbcTimeout, StdResult,
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
    _env: Env,
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

    // If the consumer name and description are set, emit an event
    if let (Some(name), Some(description)) = (&cfg.consumer_name, &cfg.consumer_description) {
        response = response
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

// Methods to handle PacketMsg variants
pub(crate) mod ibc_packet {
    use super::*;
    use babylon_apis::finality_api::Evidence;
    use babylon_proto::babylon::zoneconcierge::v1::zoneconcierge_packet_data::Packet::ConsumerSlashing;
    use babylon_proto::babylon::zoneconcierge::v1::ConsumerSlashingIbcPacket;
    use cosmwasm_std::{IbcChannel, IbcMsg};

    pub fn slashing_msg(
        env: &Env,
        channel: &IbcChannel,
        evidence: &Evidence,
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
    use crate::msg::InstantiateMsg;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_ibc_channel_open_try, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::OwnedDeps;
    use cosmwasm_vm::testing::mock_info;

    const CREATOR: &str = "creator";

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            admin: deps.api.addr_make("admin").to_string(),
            consumer_id: "consumer".to_string(),
            babylon: deps.api.addr_make("babylon"),
            is_enabled: true,
            consumer_name: None,
            consumer_description: None,
        };
        let info = mock_info(CREATOR, &[]);
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
