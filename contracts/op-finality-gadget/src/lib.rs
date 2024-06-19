use cosmwasm_std::{entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use error::ContractError;
use msg::{ExecuteMsg, InstantiateMsg};

mod finality;

pub mod contract;
pub mod error;
pub mod msg;
pub mod queries;
pub mod state;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    contract::instantiate(deps, env, info, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: msg::QueryMsg) -> StdResult<Binary> {
    contract::query(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    // TODO: contract::execute(deps, env, info, msg)
    unimplemented!();
}
