#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    Binary, Deps, DepsMut, Empty, Env, IbcBasicResponse, IbcChannelCloseMsg, IbcChannelConnectMsg,
    IbcChannelOpenMsg, IbcChannelOpenResponse, IbcPacketAckMsg, IbcPacketReceiveMsg,
    IbcPacketTimeoutMsg, IbcReceiveResponse, MessageInfo, Never, Reply, Response, StdResult,
};

use babylon_bindings::{query::BabylonQuery, BabylonMsg};

use crate::error::ContractError;
pub use crate::msg::contract::ExecuteMsg;
use crate::msg::contract::InstantiateMsg;

mod bindings;
pub mod contract;
pub mod error;
pub mod ibc;
pub mod msg;
#[cfg(test)]
mod multitest;
mod queries;
pub mod state;
mod utils;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    contract::instantiate(deps, env, info, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps<BabylonQuery>,
    env: Env,
    msg: msg::contract::QueryMsg,
) -> Result<Binary, ContractError> {
    contract::query(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    msg: Empty,
) -> Result<Response<BabylonMsg>, ContractError> {
    contract::migrate(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    contract::execute(deps, env, info, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_open(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, error::ContractError> {
    ibc::ibc_channel_open(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_connect(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    msg: IbcChannelConnectMsg,
) -> Result<IbcBasicResponse, ContractError> {
    ibc::ibc_channel_connect(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_channel_close(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    msg: IbcChannelCloseMsg,
) -> StdResult<IbcBasicResponse> {
    ibc::ibc_channel_close(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_receive(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse<BabylonMsg>, Never> {
    ibc::ibc_packet_receive(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_ack(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    ibc::ibc_packet_ack(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn ibc_packet_timeout(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    ibc::ibc_packet_timeout(deps, env, msg)
}
