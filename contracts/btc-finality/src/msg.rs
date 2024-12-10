use cosmwasm_schema::{cw_serde, QueryResponses};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::state::config::Config, babylon_apis::finality_api::PubRandCommit,
    cw_controllers::AdminResponse,
};

use babylon_apis::finality_api::{Evidence, IndexedBlock};

use crate::state::config::Params;

#[cw_serde]
#[derive(Default)]
pub struct InstantiateMsg {
    pub params: Option<Params>,
    pub admin: Option<String>,
}

pub type ExecuteMsg = babylon_apis::finality_api::ExecuteMsg;

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// `Config` returns the current configuration of the btc-finality contract
    #[returns(Config)]
    Config {},
    /// `Params` returns the current Consumer-specific parameters of the btc-finality contract
    #[returns(Params)]
    Params {},
    /// `Admin` returns the current admin of the contract
    #[returns(AdminResponse)]
    Admin {},
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
pub struct FinalitySignatureResponse {
    pub signature: Vec<u8>,
}

#[cw_serde]
pub struct BlocksResponse {
    pub blocks: Vec<IndexedBlock>,
}

#[cw_serde]
pub struct EvidenceResponse {
    pub evidence: Option<Evidence>,
}
