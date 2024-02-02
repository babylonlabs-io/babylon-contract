use crate::msg::btc_header::BtcHeader;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{StdError, StdResult};

const BABYLON_TAG_BYTES: usize = 4;

// common functions for contract msgs
pub trait ContractMsg {
    fn validate(&self) -> StdResult<()>;
    fn babylon_tag_to_bytes(&self) -> StdResult<Vec<u8>>;
}

#[cw_serde]
pub struct InstantiateMsg {
    pub network: babylon_bitcoin::chain_params::Network,
    /// babylon_tag is a string encoding four bytes used for identification / tagging of the Babylon zone.
    /// NOTE: this is a hex string, not raw bytes
    pub babylon_tag: String,
    pub btc_confirmation_depth: u64,
    pub checkpoint_finalization_timeout: u64,
    // notify_cosmos_zone indicates whether to send Cosmos zone messages notifying BTC-finalised headers
    // NOTE: if set true, then the Cosmos zone needs to integrate the corresponding message handler as well
    pub notify_cosmos_zone: bool,
}

impl ContractMsg for InstantiateMsg {
    fn validate(&self) -> StdResult<()> {
        if self.babylon_tag.len() != BABYLON_TAG_BYTES * 2 {
            return Err(StdError::invalid_data_size(
                BABYLON_TAG_BYTES * 2,
                self.babylon_tag.len(),
            ));
        }
        let _ = self.babylon_tag_to_bytes()?;
        Ok(())
    }

    fn babylon_tag_to_bytes(&self) -> StdResult<Vec<u8>> {
        hex::decode(&self.babylon_tag).map_err(|_| {
            StdError::generic_err(format!(
                "babylon_tag is not a valid hex string: {}",
                self.babylon_tag
            ))
        })
    }
}

#[cw_serde]
pub enum ExecuteMsg {
    BtcHeaders {
        /// `headers` is a list of BTC headers. Typically:
        /// - A given delta of headers a user wants to add to the tip of, or fork the BTC chain.
        headers: Vec<BtcHeader>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// TODO: a boilerplate message. Replace with actual one.
    #[returns(AccountResponse)]
    Account { channel_id: String },
}

#[cw_serde]
pub struct AccountResponse {
    pub account: Option<String>,
}
