// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcHeaderInfo {
    #[prost(bytes="bytes", tag="1")]
    pub header: ::prost::bytes::Bytes,
    #[prost(bytes="bytes", tag="2")]
    pub hash: ::prost::bytes::Bytes,
    #[prost(uint64, tag="3")]
    pub height: u64,
    #[prost(bytes="bytes", tag="4")]
    pub work: ::prost::bytes::Bytes,
}
// @@protoc_insertion_point(module)
