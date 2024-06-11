use cosmwasm_std::{entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use error::ContractError;
use msg::{ExecuteMsg, InstantiateMsg};

pub mod contract;
pub mod error;
pub mod msg;
pub mod state;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    // TODO: contract::instantiate(deps, env, info, msg)
    unimplemented!();
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: msg::QueryMsg) -> StdResult<Binary> {
    // TODO: contract::query(deps, env, msg)
    unimplemented!();
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
