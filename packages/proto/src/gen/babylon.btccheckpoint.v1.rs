// @generated
/// Each provided OP_RETURN transaction can be idendtified by hash of block in
/// which transaction was included and transaction index in the block
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionKey {
    #[prost(uint32, tag="1")]
    pub index: u32,
    #[prost(bytes="bytes", tag="2")]
    pub hash: ::prost::bytes::Bytes,
}
/// Checkpoint can be composed from multiple transactions, so to identify whole
/// submission we need list of transaction keys.
/// Each submission can generally be identified by this list of (txIdx,
/// blockHash) tuples. Note: this could possibly be optimized as if transactions
/// were in one block they would have the same block hash and different indexes,
/// but each blockhash is only 33 (1  byte for prefix encoding and 32 byte hash),
/// so there should be other strong arguments for this optimization
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmissionKey {
    #[prost(message, repeated, tag="1")]
    pub key: ::prost::alloc::vec::Vec<TransactionKey>,
}
/// TransactionInfo is the info of a tx on Bitcoin,
/// including
/// - the position of the tx on BTC blockchain
/// - the full tx content
/// - the Merkle proof that this tx is on the above position
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionInfo {
    /// key is the position (txIdx, blockHash) of this tx on BTC blockchain
    /// Although it is already a part of SubmissionKey, we store it here again
    /// to make TransactionInfo self-contained.
    /// For example, storing the key allows TransactionInfo to not relay on
    /// the fact that TransactionInfo will be ordered in the same order as
    /// TransactionKeys in SubmissionKey.
    #[prost(message, optional, tag="1")]
    pub key: ::core::option::Option<TransactionKey>,
    /// transaction is the full transaction in bytes
    #[prost(bytes="bytes", tag="2")]
    pub transaction: ::prost::bytes::Bytes,
    /// proof is the Merkle proof that this tx is included in the position in `key`
    /// TODO: maybe it could use here better format as we already processed and
    /// valideated the proof?
    #[prost(bytes="bytes", tag="3")]
    pub proof: ::prost::bytes::Bytes,
}
// @@protoc_insertion_point(module)
