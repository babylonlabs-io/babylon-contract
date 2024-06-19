// @generated
/// QueryFinalityProviderRequest requests information about a finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProviderRequest {
    /// consumer id is the consumer id this finality provider is registered to
    #[prost(string, tag="1")]
    pub consumer_id: ::prost::alloc::string::String,
    /// fp_btc_pk_hex is the hex str of Bitcoin secp256k1 PK of the finality provider
    #[prost(string, tag="2")]
    pub fp_btc_pk_hex: ::prost::alloc::string::String,
}
/// QueryFinalityProviderResponse contains information about a finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalityProviderResponse {
    /// finality_provider contains the FinalityProvider
    #[prost(message, optional, tag="1")]
    pub finality_provider: ::core::option::Option<FinalityProviderResponse>,
}
/// FinalityProviderResponse defines a finality provider with voting power information.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalityProviderResponse {
    /// description defines the description terms for the finality provider.
    #[prost(message, optional, tag="1")]
    pub description: ::core::option::Option<cosmos_sdk_proto::cosmos::staking::v1beta1::Description>,
    /// commission defines the commission rate of the finality provider.
    #[prost(string, tag="2")]
    pub commission: ::prost::alloc::string::String,
    /// babylon_pk is the Babylon secp256k1 PK of this finality provider
    #[prost(message, optional, tag="3")]
    pub babylon_pk: ::core::option::Option<cosmos_sdk_proto::cosmos::crypto::secp256k1::PubKey>,
    /// btc_pk is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="bytes", tag="4")]
    pub btc_pk: ::prost::bytes::Bytes,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="5")]
    pub pop: ::core::option::Option<super::super::btcstaking::v1::ProofOfPossession>,
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="6")]
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="7")]
    pub slashed_btc_height: u64,
    /// height is the queried Babylon height
    #[prost(uint64, tag="8")]
    pub height: u64,
    /// voting_power is the voting power of this finality provider at the given height
    #[prost(uint64, tag="9")]
    pub voting_power: u64,
    /// consumer_id is the consumer id this finality provider is registered to
    #[prost(string, tag="10")]
    pub consumer_id: ::prost::alloc::string::String,
}
// @@protoc_insertion_point(module)
