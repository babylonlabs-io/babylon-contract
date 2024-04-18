use crate::state::{Config, CONFIG};
use cosmwasm_std::{Deps, StdResult};

pub fn config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}
