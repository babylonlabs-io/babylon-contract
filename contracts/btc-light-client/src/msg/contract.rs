use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{StdError, StdResult};

use crate::msg::btc_header::{BtcHeader, BtcHeaderResponse, BtcHeadersResponse};

#[cw_serde]
pub struct InstantiateMsg {
    pub network: babylon_bitcoin::chain_params::Network,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
}

impl InstantiateMsg {
    pub fn validate(&self) -> StdResult<()> {
        if self.btc_confirmation_depth == 0 {
            return Err(StdError::generic_err(
                "BTC confirmation depth must be greater than 0",
            ));
        }
        if self.checkpoint_finalization_timeout == 0 {
            return Err(StdError::generic_err(
                "Checkpoint finalization timeout must be greater than 0",
            ));
        }
        Ok(())
    }
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Initialize the BTC light client with a list of consecutive headers
    InitBtcLightClient { headers: Vec<BtcHeader> },
    /// Update the BTC light client with a list of consecutive headers
    UpdateBtcLightClient { headers: Vec<BtcHeader> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(BtcHeaderResponse)]
    BtcBaseHeader {},
    #[returns(BtcHeaderResponse)]
    BtcTipHeader {},
    #[returns(BtcHeaderResponse)]
    BtcHeader { height: u32 },
    #[returns(BtcHeaderResponse)]
    BtcHeaderByHash { hash: String },
    #[returns(BtcHeadersResponse)]
    BtcHeaders {
        start_after: Option<u32>,
        limit: Option<u32>,
        reverse: Option<bool>,
    },
}
