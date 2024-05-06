use cosmwasm_schema::{cw_serde, QueryResponses};

use babylon_apis::btc_staking_api::{ActiveBtcDelegation, FinalityProvider};

use crate::state::Config;

#[cw_serde]
pub struct InstantiateMsg {}

pub type ExecuteMsg = babylon_apis::btc_staking_api::ExecuteMsg;

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// `Config` returns the current configuration of the btc-staking contract
    #[returns(Config)]
    Config {},
    /// `FinalityProvider` returns the finality provider by its BTC public key, in hex format
    #[returns(FinalityProvider)]
    FinalityProvider { btc_pk_hex: String },
    /// `FinalityProviders` returns the list of registered finality providers
    ///
    /// `start_after` is the BTC public key of the FP to start after, or `None` to start from the beginning
    #[returns(FinalityProvidersResponse)]
    FinalityProviders {
        start_after: Option<String>,
        limit: Option<u32>,
    },
    /// `Delegation` returns delegation information by its staking tx hash, in hex format
    #[returns(ActiveBtcDelegation)]
    Delegation { staking_tx_hash_hex: String },
    /// `Delegations` returns the list of delegations
    ///
    /// `start_after` is the staking tx hash (in hex format) of the delegation to start after,
    /// or `None` to start from the beginning
    #[returns(BtcDelegationsResponse)]
    Delegations {
        start_after: Option<String>,
        limit: Option<u32>,
    },
    /// `DelegationsByFP` returns the list of staking tx hashes (in hex format) corresponding to
    /// delegations, for a given finality provider.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    /// The hashes are returned in hex format
    //TODO?: Support pagination
    #[returns(DelegationsByFPResponse)]
    DelegationsByFP { btc_pk_hex: String },
}

#[cw_serde]
pub struct FinalityProvidersResponse {
    pub fps: Vec<FinalityProvider>,
}

#[cw_serde]
pub struct BtcDelegationsResponse {
    pub delegations: Vec<ActiveBtcDelegation>,
}

#[cw_serde]
pub struct DelegationsByFPResponse {
    pub hashes: Vec<String>,
}
