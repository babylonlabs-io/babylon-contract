// @generated
/// MsgAddFinalitySig defines a message for adding a finality vote
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgAddFinalitySig {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// fp_btc_pk is the BTC PK of the finality provider that casts this vote
    #[prost(bytes="bytes", tag="2")]
    pub fp_btc_pk: ::prost::bytes::Bytes,
    /// block_height is the height of the voted block
    #[prost(uint64, tag="3")]
    pub block_height: u64,
    /// pub_rand is the public randomness committed at this height
    #[prost(bytes="bytes", tag="4")]
    pub pub_rand: ::prost::bytes::Bytes,
    /// proof is the proof that the given public randomness is committed under the commitment
    #[prost(message, optional, tag="5")]
    pub proof: ::core::option::Option<tendermint_proto::crypto::Proof>,
    /// block_app_hash is the AppHash of the voted block
    #[prost(bytes="bytes", tag="6")]
    pub block_app_hash: ::prost::bytes::Bytes,
    /// finality_sig is the finality signature to this block
    /// where finality signature is an EOTS signature, i.e.,
    /// the `s` in a Schnorr signature `(r, s)`
    /// `r` is the public randomness that is already committed by the finality provider
    #[prost(bytes="bytes", tag="7")]
    pub finality_sig: ::prost::bytes::Bytes,
}
// @@protoc_insertion_point(module)
