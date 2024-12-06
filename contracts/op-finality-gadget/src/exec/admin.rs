use babylon_bindings::BabylonMsg;
use cosmwasm_std::{DepsMut, MessageInfo, Response};

use crate::{
    error::ContractError,
    state::config::{ADMIN, IS_ENABLED},
};

// Enable or disable the finality gadget.
// Only callable by contract admin.
// If disabled, the verifier should bypass the EOTS verification logic, allowing the OP derivation
// derivation pipeline to pass through. Note this should be implemented in the verifier and is not
// enforced by the contract itself.
pub fn set_enabled(
    deps: DepsMut,
    info: MessageInfo,
    enabled: bool,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Check caller is admin
    check_admin(&deps, info)?;
    // Check if the finality gadget is already in the desired state
    if IS_ENABLED.load(deps.storage)? == enabled {
        if enabled {
            return Err(ContractError::AlreadyEnabled {});
        } else {
            return Err(ContractError::AlreadyDisabled {});
        }
    }
    // Disable finality gadget
    IS_ENABLED.save(deps.storage, &enabled)?;
    Result::Ok(Response::default())
}

// Helper function to check caller is contract admin
fn check_admin(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    // Check caller is admin
    if !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}
