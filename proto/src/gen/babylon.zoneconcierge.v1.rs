// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IndexedHeader {
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(bytes="bytes", tag="2")]
    pub hash: ::prost::bytes::Bytes,
    #[prost(uint64, tag="3")]
    pub height: u64,
    #[prost(message, optional, tag="4")]
    pub babylon_header: ::core::option::Option<tendermint_proto::types::Header>,
    #[prost(uint64, tag="5")]
    pub babylon_epoch: u64,
    #[prost(bytes="bytes", tag="6")]
    pub babylon_tx_hash: ::prost::bytes::Bytes,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Forks {
    #[prost(message, repeated, tag="3")]
    pub headers: ::prost::alloc::vec::Vec<IndexedHeader>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofEpochSealed {
    #[prost(message, repeated, tag="1")]
    pub validator_set: ::prost::alloc::vec::Vec<super::super::checkpointing::v1::ValidatorWithBlsKey>,
    #[prost(message, optional, tag="2")]
    pub proof_epoch_info: ::core::option::Option<tendermint_proto::crypto::ProofOps>,
    #[prost(message, optional, tag="3")]
    pub proof_epoch_val_set: ::core::option::Option<tendermint_proto::crypto::ProofOps>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofFinalizedChainInfo {
    #[prost(message, optional, tag="4")]
    pub proof_tx_in_block: ::core::option::Option<tendermint_proto::types::TxProof>,
    #[prost(message, optional, tag="5")]
    pub proof_header_in_epoch: ::core::option::Option<tendermint_proto::crypto::Proof>,
    #[prost(message, optional, tag="6")]
    pub proof_epoch_sealed: ::core::option::Option<ProofEpochSealed>,
    #[prost(message, repeated, tag="7")]
    pub proof_epoch_submitted: ::prost::alloc::vec::Vec<super::super::btccheckpoint::v1::TransactionInfo>,
}
// @@protoc_insertion_point(module)
