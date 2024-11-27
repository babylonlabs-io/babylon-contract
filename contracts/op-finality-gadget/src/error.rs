use babylon_merkle::error::MerkleError;
use cosmwasm_std::StdError;
use hex::FromHexError;
use thiserror::Error;

// Note: copied from contracts/btc-staking/src/error.rs
#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("Empty signature from the delegator")]
    EmptySignature,
    #[error("EOTS error: {0}")]
    EotsError(#[from] eots::Error),
    #[error("Failed to verify signature: {0}")]
    FailedSignatureVerification(String),
    #[error("The chain has not reached the given height yet")]
    HeightTooHigh,
    #[error("{0}")]
    HexError(#[from] FromHexError),
    #[error("The inclusion proof for height {0} does not correspond to the given height ({1})")]
    InvalidFinalitySigHeight(u64, u64),
    #[error("The total amount of public randomnesses in the proof ({0}) does not match the amount of public committed randomness ({1})")]
    InvalidFinalitySigAmount(u64, u64),
    #[error("The start height ({0}) has overlap with the height of the highest public randomness committed ({1})")]
    InvalidPubRandHeight(u64, u64),
    #[error("Invalid finality signature: {0}")]
    InvalidSignature(String),
    #[error("{0}")]
    MerkleError(#[from] MerkleError),
    #[error("Public randomness not found for finality provider {0} at height {1}")]
    MissingPubRandCommit(String, u64),
    #[error("{0}")]
    SecP256K1Error(String), // TODO: inherit errors from k256
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("Failed to query block voters for block {0} with hash {1}. {2}")]
    QueryBlockVoterError(u64, String, String),
    #[error("Finality provider not found for consumer {0} with pubkey {1}")]
    NotFoundFinalityProvider(String, String),
    #[error("Failed to query the voting power of the finality provider {0}")]
    FailedFetchVotingPower(String),
    #[error("Empty block range")]
    EmptyBlockRange,
    #[error("Caller is not the admin")]
    Unauthorized,
    #[error("Finality gadget is already enabled")]
    AlreadyEnabled,
    #[error("Finality gadget is already disabled")]
    AlreadyDisabled,
}
