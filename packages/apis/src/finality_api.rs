/// Finality messages / API
/// The definitions here roughly follow the same structure as the equivalent IBC protobuf pub struct types,
/// defined in `packages/proto/src/gen/babylon.finality.v1.rs`
use cosmwasm_schema::cw_serde;

use crate::Bytes;

/// `IndexedBlock` is the necessary metadata and finalization status of a block
#[cw_serde]
pub struct IndexedBlock {
    /// `height` is the height of the block
    pub height: u64,
    /// `app_hash` is the AppHash of the block
    pub app_hash: Bytes,
    /// `finalized` indicates whether the IndexedBlock is finalised by 2/3 of the finality
    /// providers or not
    pub finalized: bool,
}

/// `PubRandCommit` is a commitment to a series of public randomness.
/// Currently, the commitment is a root of a Merkle tree that includes a series of public randomness
/// values
#[cw_serde]
pub struct PubRandCommit {
    /// `start_height` is the height of the first commitment
    pub start_height: u64,
    /// `num_pub_rand` is the number of committed public randomness
    pub num_pub_rand: u64,
    /// `commitment` is the value of the commitment.
    /// Currently, it's the root of the Merkle tree constructed by the public randomness
    pub commitment: Bytes,
}

impl PubRandCommit {
    /// `in_range` checks if the given height is within the range of the commitment
    pub fn in_range(&self, height: u64) -> bool {
        self.start_height <= height && height <= self.end_height()
    }

    /// `end_height` returns the height of the last commitment
    pub fn end_height(&self) -> u64 {
        self.start_height + self.num_pub_rand - 1
    }
}

/// Evidence is the evidence that a finality provider has signed finality
/// signatures with correct public randomness on two conflicting Babylon headers
#[cw_serde]
pub struct Evidence {
    /// `fp_btc_pk` is the BTC PK of the finality provider that casts this vote
    pub fp_btc_pk: Bytes,
    /// `block_height` is the height of the conflicting blocks
    pub block_height: u64,
    /// `pub_rand is` the public randomness the finality provider has committed to.
    /// Deserializes `SchnorrPubRand`
    pub pub_rand: Bytes,
    /// `canonical_app_hash` is the AppHash of the canonical block
    pub canonical_app_hash: Bytes,
    /// `fork_app_hash` is the AppHash of the fork block
    pub fork_app_hash: Bytes,
    /// `canonical_finality_sig` is the finality signature to the canonical block,
    /// where finality signature is an EOTS signature, i.e.,
    /// the `s` in a Schnorr signature `(r, s)`
    /// `r` is the public randomness that is already committed by the finality provider
    /// Deserializes to `SchnorrEOTSSig`
    pub canonical_finality_sig: Bytes,
    /// `fork_finality_sig` is the finality signature to the fork block,
    /// where finality signature is an EOTS signature.
    /// Deserializes to `SchnorrEOTSSig`
    pub fork_finality_sig: Bytes,
}
