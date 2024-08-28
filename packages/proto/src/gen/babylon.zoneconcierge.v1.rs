// @generated
/// IndexedHeader is the metadata of a CZ header
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IndexedHeader {
    /// chain_id is the unique ID of the chain
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    /// hash is the hash of this header
    #[prost(bytes="bytes", tag="2")]
    pub hash: ::prost::bytes::Bytes,
    /// height is the height of this header on CZ ledger
    /// (hash, height) jointly provides the position of the header on CZ ledger
    #[prost(uint64, tag="3")]
    pub height: u64,
    /// time is the timestamp of this header on CZ ledger
    /// it is needed for CZ to unbond all mature validators/delegations
    /// before this timestamp when this header is BTC-finalised
    #[prost(message, optional, tag="4")]
    pub time: ::core::option::Option<::pbjson_types::Timestamp>,
    /// babylon_header_hash is the hash of the babylon block that includes this CZ
    /// header
    #[prost(bytes="bytes", tag="5")]
    pub babylon_header_hash: ::prost::bytes::Bytes,
    /// babylon_header_height is the height of the babylon block that includes this CZ
    /// header
    #[prost(uint64, tag="6")]
    pub babylon_header_height: u64,
    /// epoch is the epoch number of this header on Babylon ledger
    #[prost(uint64, tag="7")]
    pub babylon_epoch: u64,
    /// babylon_tx_hash is the hash of the tx that includes this header
    /// (babylon_block_height, babylon_tx_hash) jointly provides the position of
    /// the header on Babylon ledger
    #[prost(bytes="bytes", tag="8")]
    pub babylon_tx_hash: ::prost::bytes::Bytes,
}
/// Forks is a list of non-canonical `IndexedHeader`s at the same height.
/// For example, assuming the following blockchain
/// ```
/// A <- B <- C <- D <- E
///             \ -- D1
///             \ -- D2
/// ```
/// Then the fork will be {[D1, D2]} where each item is in struct `IndexedBlock`.
///
/// Note that each `IndexedHeader` in the fork should have a valid quorum
/// certificate. Such forks exist since Babylon considers CZs might have
/// dishonest majority. Also note that the IBC-Go implementation will only
/// consider the first header in a fork valid, since the subsequent headers
/// cannot be verified without knowing the validator set in the previous header.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Forks {
    /// blocks is the list of non-canonical indexed headers at the same height
    #[prost(message, repeated, tag="3")]
    pub headers: ::prost::alloc::vec::Vec<IndexedHeader>,
}
/// ChainInfo is the information of a CZ
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainInfo {
    /// chain_id is the ID of the chain
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    /// latest_header is the latest header in CZ's canonical chain
    #[prost(message, optional, tag="2")]
    pub latest_header: ::core::option::Option<IndexedHeader>,
    /// latest_forks is the latest forks, formed as a series of IndexedHeader (from
    /// low to high)
    #[prost(message, optional, tag="3")]
    pub latest_forks: ::core::option::Option<Forks>,
    /// timestamped_headers_count is the number of timestamped headers in CZ's
    /// canonical chain
    #[prost(uint64, tag="4")]
    pub timestamped_headers_count: u64,
}
/// FinalizedChainInfo is the information of a CZ that is BTC-finalised
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizedChainInfo {
    /// chain_id is the ID of the chain
    #[prost(string, tag="1")]
    pub chain_id: ::prost::alloc::string::String,
    /// finalized_chain_info is the info of the CZ
    #[prost(message, optional, tag="2")]
    pub finalized_chain_info: ::core::option::Option<ChainInfo>,
    /// epoch_info is the metadata of the last BTC-finalised epoch
    #[prost(message, optional, tag="3")]
    pub epoch_info: ::core::option::Option<super::super::epoching::v1::Epoch>,
    /// raw_checkpoint is the raw checkpoint of this epoch
    #[prost(message, optional, tag="4")]
    pub raw_checkpoint: ::core::option::Option<super::super::checkpointing::v1::RawCheckpoint>,
    /// btc_submission_key is position of two BTC txs that include the raw
    /// checkpoint of this epoch
    #[prost(message, optional, tag="5")]
    pub btc_submission_key: ::core::option::Option<super::super::btccheckpoint::v1::SubmissionKey>,
    /// proof is the proof that the chain info is finalized
    #[prost(message, optional, tag="6")]
    pub proof: ::core::option::Option<ProofFinalizedChainInfo>,
}
/// ProofEpochSealed is the proof that an epoch is sealed by the sealer header,
/// i.e., the 2nd header of the next epoch With the access of metadata
/// - Metadata of this epoch, which includes the sealer header
/// - Raw checkpoint of this epoch
/// The verifier can perform the following verification rules:
/// - The raw checkpoint's `app_hash` is same as in the sealer header
/// - More than 2/3 (in voting power) validators in the validator set of this
/// epoch have signed `app_hash` of the sealer header
/// - The epoch metadata is committed to the `app_hash` of the sealer header
/// - The validator set is committed to the `app_hash` of the sealer header
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofEpochSealed {
    /// validator_set is the validator set of the sealed epoch
    /// This validator set has generated a BLS multisig on `app_hash` of
    /// the sealer header
    #[prost(message, repeated, tag="1")]
    pub validator_set: ::prost::alloc::vec::Vec<super::super::checkpointing::v1::ValidatorWithBlsKey>,
    /// proof_epoch_info is the Merkle proof that the epoch's metadata is committed
    /// to `app_hash` of the sealer header
    #[prost(message, optional, tag="2")]
    pub proof_epoch_info: ::core::option::Option<tendermint_proto::crypto::ProofOps>,
    /// proof_epoch_info is the Merkle proof that the epoch's validator set is
    /// committed to `app_hash` of the sealer header
    #[prost(message, optional, tag="3")]
    pub proof_epoch_val_set: ::core::option::Option<tendermint_proto::crypto::ProofOps>,
}
/// ProofFinalizedChainInfo is a set of proofs that attest a chain info is
/// BTC-finalised
///
///
/// The following fields include proofs that attest the chain info is
/// BTC-finalised
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofFinalizedChainInfo {
    /// proof_cz_header_in_epoch is the proof that the CZ header is timestamped
    /// within a certain epoch
    #[prost(message, optional, tag="1")]
    pub proof_cz_header_in_epoch: ::core::option::Option<tendermint_proto::crypto::ProofOps>,
    /// proof_epoch_sealed is the proof that the epoch is sealed
    #[prost(message, optional, tag="2")]
    pub proof_epoch_sealed: ::core::option::Option<ProofEpochSealed>,
    /// proof_epoch_submitted is the proof that the epoch's checkpoint is included
    /// in BTC ledger It is the two TransactionInfo in the best (i.e., earliest)
    /// checkpoint submission
    #[prost(message, repeated, tag="3")]
    pub proof_epoch_submitted: ::prost::alloc::vec::Vec<super::super::btccheckpoint::v1::TransactionInfo>,
}
/// ZoneconciergePacketData is the message that defines the IBC packets of
/// ZoneConcierge
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ZoneconciergePacketData {
    /// packet is the actual message carried in the IBC packet
    #[prost(oneof="zoneconcierge_packet_data::Packet", tags="1, 2, 3, 4")]
    pub packet: ::core::option::Option<zoneconcierge_packet_data::Packet>,
}
/// Nested message and enum types in `ZoneconciergePacketData`.
pub mod zoneconcierge_packet_data {
    /// packet is the actual message carried in the IBC packet
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Packet {
        #[prost(message, tag="1")]
        BtcTimestamp(super::BtcTimestamp),
        #[prost(message, tag="2")]
        BtcStaking(super::super::super::btcstaking::v1::BtcStakingIbcPacket),
        #[prost(message, tag="3")]
        ConsumerRegister(super::ConsumerRegisterIbcPacket),
        #[prost(message, tag="4")]
        ConsumerSlashing(super::ConsumerSlashingIbcPacket),
    }
}
/// BTCTimestamp is a BTC timestamp that carries information of a BTC-finalised epoch
/// It includes a number of BTC headers, a raw checkpoint, an epoch metadata, and
/// a CZ header if there exists CZ headers checkpointed to this epoch.
/// Upon a newly finalised epoch in Babylon, Babylon will send a BTC timestamp to each
/// Cosmos zone that has phase-2 integration with Babylon via IBC.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcTimestamp {
    /// header is the last CZ header in the finalized Babylon epoch
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<IndexedHeader>,
    //
    // Data for BTC light client

    /// btc_headers is BTC headers between
    /// - the block AFTER the common ancestor of BTC tip at epoch `lastFinalizedEpoch-1` and BTC tip at epoch `lastFinalizedEpoch`
    /// - BTC tip at epoch `lastFinalizedEpoch`
    /// where `lastFinalizedEpoch` is the last finalised epoch in Babylon
    #[prost(message, repeated, tag="2")]
    pub btc_headers: ::prost::alloc::vec::Vec<super::super::btclightclient::v1::BtcHeaderInfo>,
    //
    // Data for Babylon epoch chain

    /// epoch_info is the metadata of the sealed epoch
    #[prost(message, optional, tag="3")]
    pub epoch_info: ::core::option::Option<super::super::epoching::v1::Epoch>,
    /// raw_checkpoint is the raw checkpoint that seals this epoch
    #[prost(message, optional, tag="4")]
    pub raw_checkpoint: ::core::option::Option<super::super::checkpointing::v1::RawCheckpoint>,
    /// btc_submission_key is position of two BTC txs that include the raw checkpoint of this epoch
    #[prost(message, optional, tag="5")]
    pub btc_submission_key: ::core::option::Option<super::super::btccheckpoint::v1::SubmissionKey>,
    ///
    /// Proofs that the header is finalized
    #[prost(message, optional, tag="6")]
    pub proof: ::core::option::Option<ProofFinalizedChainInfo>,
}
/// ConsumerRegisterIBCPacket defines the packet data for Consumer registration
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsumerRegisterIbcPacket {
    /// consumer_name is a unique identifier for the consumer chain
    #[prost(string, tag="1")]
    pub consumer_name: ::prost::alloc::string::String,
    /// consumer_description is a brief explanation of the consumer chain's purpose
    #[prost(string, tag="2")]
    pub consumer_description: ::prost::alloc::string::String,
}
/// ConsumerSlashingIBCPacket defines the slashing information that a Consumer sends to Babylon's ZoneConcierge upon a
/// Consumer slashing event.
/// It includes the FP public key, the Consumer block height at the slashing event, and the double sign evidence.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsumerSlashingIbcPacket {
    /// / evidence is the FP slashing evidence that the Consumer sends to Babylon
    #[prost(message, optional, tag="1")]
    pub evidence: ::core::option::Option<super::super::finality::v1::Evidence>,
}
/// QueryFinalizedChainsInfoResponse is response type for the
/// Query/FinalizedChainsInfo RPC method.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryFinalizedChainsInfoResponse {
    #[prost(message, repeated, tag="1")]
    pub finalized_chains_info: ::prost::alloc::vec::Vec<FinalizedChainInfo>,
}
// @@protoc_insertion_point(module)
