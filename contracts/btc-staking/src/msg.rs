use cosmwasm_schema::{cw_serde, QueryResponses};
use cw_controllers::AdminResponse;

use babylon_apis::btc_staking_api::{ActiveBtcDelegation, FinalityProvider};
use babylon_apis::finality_api::{Evidence, IndexedBlock, PubRandCommit};

use crate::state::config::{Config, Params};
use crate::state::staking::BtcDelegation;

#[cw_serde]
#[derive(Default)]
pub struct InstantiateMsg {
    pub params: Option<Params>,
    pub admin: Option<String>,
}

pub type ExecuteMsg = babylon_apis::btc_staking_api::ExecuteMsg;

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// `Config` returns the current configuration of the btc-staking contract
    #[returns(Config)]
    Config {},
    /// `Params` returns the current Consumer-specific parameters of the btc-staking contract
    #[returns(Params)]
    Params {},
    /// `Admin` returns the current admin of the contract
    #[returns(AdminResponse)]
    Admin {},
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
    /// `Delegations` return the list of delegations
    ///
    /// `start_after` is the staking tx hash (in hex format) of the delegation to start after,
    /// or `None` to start from the beginning.
    /// `limit` is the maximum number of delegations to return.
    /// `active` is an optional filter to return only active delegations
    #[returns(BtcDelegationsResponse)]
    Delegations {
        start_after: Option<String>,
        limit: Option<u32>,
        active: Option<bool>,
    },
    /// `DelegationsByFP` returns the list of staking tx hashes (in hex format) corresponding to
    /// delegations, for a given finality provider.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    /// The hashes are returned in hex format
    //TODO?: Support pagination
    #[returns(DelegationsByFPResponse)]
    DelegationsByFP { btc_pk_hex: String },
    /// `FinalityProviderInfo` returns the finality provider information by its BTC public key,
    /// in hex format
    /// The information includes the aggregated power of the finality provider.
    ///
    /// `height` is the optional block height at which the power is being aggregated.
    /// If `height` is not provided, the latest aggregated power is returned
    #[returns(FinalityProviderInfo)]
    FinalityProviderInfo {
        btc_pk_hex: String,
        height: Option<u64>,
    },
    /// `FinalityProvidersByPower` returns the list of finality provider infos sorted by their
    /// aggregated power, in descending order.
    ///
    /// `start_after` is the BTC public key of the FP to start after, or `None` to start from the top
    #[returns(FinalityProvidersByPowerResponse)]
    FinalityProvidersByPower {
        start_after: Option<FinalityProviderInfo>,
        limit: Option<u32>,
    },
    /// `FinalitySignature` returns the signature of the finality provider for a given block height
    ///
    #[returns(FinalitySignatureResponse)]
    FinalitySignature { btc_pk_hex: String, height: u64 },
    /// `PubRandCommit` returns the public random commitments for a given FP.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    ///
    /// `start_after` is the height of to start after (before, if `reverse` is `true`),
    /// or `None` to start from the beginning (end, if `reverse` is `true`).
    /// `limit` is the maximum number of commitments to return.
    /// `reverse` is an optional flag to return the commitments in reverse order
    #[returns(PubRandCommit)]
    PubRandCommit {
        btc_pk_hex: String,
        start_after: Option<u64>,
        limit: Option<u32>,
        reverse: Option<bool>,
    },
    /// `FirstPubRandCommit` returns the first public random commitment (if any) for a given FP.
    ///
    /// It's a convenience shortcut of `PubRandCommit` with a `limit` of 1, and `reverse` set to
    /// false.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    #[returns(Option<PubRandCommit>)]
    FirstPubRandCommit { btc_pk_hex: String },
    /// `LastPubRandCommit` returns the last public random commitment (if any) for a given FP.
    ///
    /// It's a convenience shortcut of `PubRandCommit` with a `limit` of 1, and `reverse` set to
    /// true.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    #[returns(Option<PubRandCommit>)]
    LastPubRandCommit { btc_pk_hex: String },
    /// `ActivatedHeight` returns the height at which the contract gets its first delegation, if any
    ///
    #[returns(ActivatedHeightResponse)]
    ActivatedHeight {},
    /// `Block` returns the indexed block information at height
    ///
    #[returns(IndexedBlock)]
    Block { height: u64 },
    /// `Blocks` return the list of indexed blocks.
    ///
    /// `start_after` is the height of the block to start after (before, if `reverse` is `true`),
    /// or `None` to start from the beginning (end, if `reverse` is `true`).
    /// `limit` is the maximum number of blocks to return.
    /// `finalised` is an optional filter to return only finalised blocks.
    /// `reverse` is an optional flag to return the blocks in reverse order
    #[returns(BlocksResponse)]
    Blocks {
        start_after: Option<u64>,
        limit: Option<u32>,
        finalised: Option<bool>,
        reverse: Option<bool>,
    },
    /// `Evidence` returns the evidence for a given FP and block height
    #[returns(EvidenceResponse)]
    Evidence { btc_pk_hex: String, height: u64 },
}

#[cw_serde]
pub struct FinalityProvidersResponse {
    pub fps: Vec<FinalityProvider>,
}

#[cw_serde]
pub struct BtcDelegationsResponse {
    pub delegations: Vec<BtcDelegation>,
}

#[cw_serde]
pub struct DelegationsByFPResponse {
    pub hashes: Vec<String>,
}

#[cw_serde]
pub struct FinalityProvidersByPowerResponse {
    pub fps: Vec<FinalityProviderInfo>,
}

#[cw_serde]
pub struct FinalityProviderInfo {
    /// `btc_pk_hex` is the Bitcoin secp256k1 PK of this finality provider.
    /// The PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// `power` is the aggregated power of this finality provider.
    /// The power is calculated based on the amount of BTC delegated to this finality provider
    pub power: u64,
}

#[cw_serde]
pub struct FinalitySignatureResponse {
    pub signature: Vec<u8>,
}

#[cw_serde]
pub struct ActivatedHeightResponse {
    pub height: u64,
}

#[cw_serde]
pub struct BlocksResponse {
    pub blocks: Vec<IndexedBlock>,
}

#[cw_serde]
pub struct EvidenceResponse {
    pub evidence: Option<Evidence>,
}
