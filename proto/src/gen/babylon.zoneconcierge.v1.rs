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
    pub time: ::core::option::Option<::pbjson_types::Timestamp>,
    #[prost(message, optional, tag="5")]
    pub babylon_header: ::core::option::Option<tendermint_proto::types::Header>,
    #[prost(uint64, tag="6")]
    pub babylon_epoch: u64,
    #[prost(bytes="bytes", tag="7")]
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
pub struct ChainInfo {
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub latest_header: ::core::option::Option<IndexedHeader>,
    #[prost(message, optional, tag="3")]
    pub latest_forks: ::core::option::Option<Forks>,
    #[prost(uint64, tag="4")]
    pub timestamped_headers_count: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizedChainInfo {
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub finalized_chain_info: ::core::option::Option<ChainInfo>,
    #[prost(message, optional, tag="3")]
    pub epoch_info: ::core::option::Option<super::super::epoching::v1::Epoch>,
    #[prost(message, optional, tag="4")]
    pub raw_checkpoint: ::core::option::Option<super::super::checkpointing::v1::RawCheckpoint>,
    #[prost(message, optional, tag="5")]
    pub btc_submission_key: ::core::option::Option<super::super::btccheckpoint::v1::SubmissionKey>,
    #[prost(message, optional, tag="6")]
    pub proof: ::core::option::Option<ProofFinalizedChainInfo>,
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ZoneconciergePacketData {
    #[prost(oneof="zoneconcierge_packet_data::Packet", tags="1")]
    pub packet: ::core::option::Option<zoneconcierge_packet_data::Packet>,
}
/// Nested message and enum types in `ZoneconciergePacketData`.
pub mod zoneconcierge_packet_data {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Packet {
        #[prost(message, tag="1")]
        BtcTimestamp(super::BtcTimestamp),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcTimestamp {
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<IndexedHeader>,
    #[prost(message, repeated, tag="2")]
    pub btc_headers: ::prost::alloc::vec::Vec<super::super::btclightclient::v1::BtcHeaderInfo>,
    #[prost(message, optional, tag="3")]
    pub epoch_info: ::core::option::Option<super::super::epoching::v1::Epoch>,
    #[prost(message, optional, tag="4")]
    pub raw_checkpoint: ::core::option::Option<super::super::checkpointing::v1::RawCheckpoint>,
    #[prost(message, optional, tag="5")]
    pub btc_submission_key: ::core::option::Option<super::super::btccheckpoint::v1::SubmissionKey>,
    #[prost(message, optional, tag="6")]
    pub proof: ::core::option::Option<ProofFinalizedChainInfo>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalizedChainsInfoResponse {
    #[prost(message, repeated, tag="1")]
    pub finalized_chains_info: ::prost::alloc::vec::Vec<FinalizedChainInfo>,
}
// @@protoc_insertion_point(module)
