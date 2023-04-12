use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::ContractResult;

#[cw_serde]
pub struct InstantiateMsg {
    pub network: babylon_bitcoin::chain_params::Network,
    pub btc_confirmation_depth: u64,
    pub checkpoint_finalization_timeout: u64,
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

#[cw_serde]
pub enum PacketMsg {
    WhoAmI {},
}

/// All acknowledgements are wrapped in `ContractResult`.
/// The success value depends on the PacketMsg variant.
pub type AcknowledgementMsg<T> = ContractResult<T>;

/// This is the success response we send on ack for PacketMsg::WhoAmI.
/// Return the caller's account address on the remote chain
#[cw_serde]
pub struct WhoAmIResponse {
    pub account: String,
}
