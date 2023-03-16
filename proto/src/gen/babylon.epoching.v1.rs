// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Epoch {
    #[prost(uint64, tag="1")]
    pub epoch_number: u64,
    #[prost(uint64, tag="2")]
    pub current_epoch_interval: u64,
    #[prost(uint64, tag="3")]
    pub first_block_height: u64,
    #[prost(message, optional, tag="4")]
    pub last_block_header: ::core::option::Option<tendermint_proto::types::Header>,
    #[prost(bytes="bytes", tag="5")]
    pub app_hash_root: ::prost::bytes::Bytes,
    #[prost(message, optional, tag="6")]
    pub sealer_header: ::core::option::Option<tendermint_proto::types::Header>,
}
// @@protoc_insertion_point(module)
