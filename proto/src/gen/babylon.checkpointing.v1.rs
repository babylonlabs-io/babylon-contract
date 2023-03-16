// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValidatorWithBlsKeySet {
    #[prost(message, repeated, tag="1")]
    pub val_set: ::prost::alloc::vec::Vec<ValidatorWithBlsKey>,
}
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RawCheckpoint {
    #[prost(uint64, tag="1")]
    pub epoch_num: u64,
    #[prost(bytes="bytes", tag="2")]
    pub last_commit_hash: ::prost::bytes::Bytes,
    #[prost(bytes="bytes", tag="3")]
    pub bitmap: ::prost::bytes::Bytes,
    #[prost(bytes="bytes", tag="4")]
    pub bls_multi_sig: ::prost::bytes::Bytes,
}
// @@protoc_insertion_point(module)
