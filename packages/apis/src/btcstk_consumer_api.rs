/// BTC staking consumer messages / API
/// The definitions here follow the same structure as the equivalent protobuf message types,
/// defined in `packages/proto/src/gen/babylon.btcstkconsumer.v1.rs`
use cosmwasm_schema::cw_serde;

/// QueryFinalityProviderResponse contains information about a finality provider
#[cw_serde]
pub struct QueryFinalityProviderResponse {
    /// finality_provider contains the FinalityProvider
    pub finality_provider: Option<FinalityProviderResponse>,
}

/// FinalityProviderResponse defines a finality provider with voting power information.
#[cw_serde]
pub struct FinalityProviderResponse {
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    pub slashed_btc_height: u64,
    /// height is the queried Babylon height
    pub height: u64,
    /// voting_power is the voting power of this finality provider at the given height
    pub voting_power: u64,
    /// consumer_id is the consumer id this finality provider is registered to
    pub consumer_id: String,
}
