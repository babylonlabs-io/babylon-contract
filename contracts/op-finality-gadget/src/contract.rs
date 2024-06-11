use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{ADMIN, CONSUMER_CHAIN_ID};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw_utils::maybe_addr;

pub fn instantiate(
    mut deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let admin_addr = maybe_addr(deps.api, Some(msg.admin))?;

    ADMIN.set(deps.branch(), admin_addr)?;

    CONSUMER_CHAIN_ID.save(deps.storage, &msg.consumer_id)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    unimplemented!();
}

pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    unimplemented!();
}
