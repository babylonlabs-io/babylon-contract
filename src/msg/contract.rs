use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{StdError, StdResult};

const BABYLON_TAG_LEN: usize = 4;

// common functions for contract msgs
pub trait ContractMsg {
    fn validate(&self) -> StdResult<()>;
}

#[cw_serde]
pub struct InstantiateMsg {
    pub network: babylon_bitcoin::chain_params::Network,
    pub babylon_tag: String,
    pub btc_confirmation_depth: u64,
    pub checkpoint_finalization_timeout: u64,
}

impl ContractMsg for InstantiateMsg {
    fn validate(&self) -> StdResult<()> {
        if self.babylon_tag.as_bytes().len() != BABYLON_TAG_LEN {
            return Err(StdError::invalid_data_size(
                BABYLON_TAG_LEN,
                self.babylon_tag.as_bytes().len(),
            ));
        }

        Ok(())
    }
}

#[cw_serde]
pub enum ExecuteMsg {
    Placeholder {}, // TODO: remove
}

impl ContractMsg for ExecuteMsg {
    fn validate(&self) -> StdResult<()> {
        Ok(())
    }
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// TODO: a boilerplate message. Replace with actual one.
    #[returns(AccountResponse)]
    Account { channel_id: String },
}

impl ContractMsg for QueryMsg {
    fn validate(&self) -> StdResult<()> {
        Ok(())
    }
}

#[cw_serde]
pub struct AccountResponse {
    pub account: Option<String>,
}
