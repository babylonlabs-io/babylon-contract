use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub network: babylon_bitcoin::chain_params::Network,
    pub btc_confirmation_depth: u64,
    pub checkpoint_finalization_timeout: u64,
}

#[cw_serde]
pub enum ExecuteMsg {
    Placeholder {}, // TODO: remove
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
