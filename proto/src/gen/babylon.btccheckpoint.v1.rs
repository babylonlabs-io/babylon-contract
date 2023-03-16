// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionKey {
    #[prost(uint32, tag="1")]
    pub index: u32,
    #[prost(bytes="bytes", tag="2")]
    pub hash: ::prost::bytes::Bytes,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionInfo {
    #[prost(message, optional, tag="1")]
    pub key: ::core::option::Option<TransactionKey>,
    #[prost(bytes="bytes", tag="2")]
    pub transaction: ::prost::bytes::Bytes,
    #[prost(bytes="bytes", tag="3")]
    pub proof: ::prost::bytes::Bytes,
}
// @@protoc_insertion_point(module)
