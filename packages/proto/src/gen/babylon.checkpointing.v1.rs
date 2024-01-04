// @generated
/// ValidatorWithBLSSet defines a set of validators with their BLS public keys
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValidatorWithBlsKeySet {
    #[prost(message, repeated, tag="1")]
    pub val_set: ::prost::alloc::vec::Vec<ValidatorWithBlsKey>,
}
/// ValidatorWithBlsKey couples validator address, voting power, and its bls
/// public key
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValidatorWithBlsKey {
    #[prost(string, tag="1")]
    pub validator_address: ::prost::alloc::string::String,
    #[prost(bytes="bytes", tag="2")]
    pub bls_pub_key: ::prost::bytes::Bytes,
    #[prost(uint64, tag="3")]
    pub voting_power: u64,
}
/// RawCheckpoint wraps the BLS multi sig with meta data
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RawCheckpoint {
    /// epoch_num defines the epoch number the raw checkpoint is for
    #[prost(uint64, tag="1")]
    pub epoch_num: u64,
    /// block_hash defines the 'BlockID.Hash', which is the hash of
    /// the block that individual BLS sigs are signed on
    #[prost(bytes="bytes", tag="2")]
    pub block_hash: ::prost::bytes::Bytes,
    /// bitmap defines the bitmap that indicates the signers of the BLS multi sig
    #[prost(bytes="bytes", tag="3")]
    pub bitmap: ::prost::bytes::Bytes,
    /// bls_multi_sig defines the multi sig that is aggregated from individual BLS
    /// sigs
    #[prost(bytes="bytes", tag="4")]
    pub bls_multi_sig: ::prost::bytes::Bytes,
}
// @@protoc_insertion_point(module)
