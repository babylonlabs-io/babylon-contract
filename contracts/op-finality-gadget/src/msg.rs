use crate::state::config::Config;
use babylon_apis::finality_api::PubRandCommit;
use babylon_merkle::Proof;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: String,
    pub consumer_id: String,
    pub activated_height: u64,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// `Config` returns the configuration of the op-finality-gadget contract
    #[returns(Config)]
    Config {},
    #[returns(BlockFinalizedResponse)]
    BlockFinalized {
        height: u64,
        hash: String,
        btc_height: u64,
    },
    /// `LastPubRandCommit` returns the last public random commitments for a given FP.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    #[returns(PubRandCommit)]
    LastPubRandCommit { btc_pk_hex: String },
}

#[cw_serde]
pub struct BlockFinalizedResponse {
    pub finalized: bool,
}

// Note: copied from packages/apis/src/btc_staking_api.rs
#[cw_serde]
pub enum ExecuteMsg {
    CommitPublicRandomness {
        /// `fp_pubkey_hex` is the BTC PK of the finality provider that commits the public randomness
        fp_pubkey_hex: String,
        /// `start_height` is the start block height of the list of public randomness
        start_height: u64,
        /// `num_pub_rand` is the amount of public randomness committed
        num_pub_rand: u64,
        /// `commitment` is the commitment of these public randomness values.
        /// Currently, it's the root of the Merkle tree that includes the public randomness
        commitment: Binary,
        /// `signature` is the signature on (start_height || num_pub_rand || commitment) signed by
        /// the SK corresponding to `fp_pubkey_hex`.
        /// This prevents others committing public randomness on behalf of `fp_pubkey_hex`
        signature: Binary,
    },
    /// Submit Finality Signature.
    ///
    /// This is a message that can be called by a finality provider to submit their finality
    /// signature to the Consumer chain.
    /// The signature is verified by the Consumer chain using the finality provider's public key
    ///
    /// This message is equivalent to the `MsgAddFinalitySig` message in the Babylon finality protobuf
    /// defs.
    // TODO: Move to its own module / contract
    SubmitFinalitySignature {
        fp_pubkey_hex: String,
        height: u64,
        pub_rand: Binary,
        proof: Proof,
        block_hash: Binary,
        signature: Binary,
    },
}
