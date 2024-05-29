use bitcoin::hashes::FromSliceError;
use bitcoin::hex::HexToArrayError;
use thiserror::Error;

use cosmwasm_std::StdError;
use cw_controllers::AdminError;
use cw_utils::PaymentError;
use prost::DecodeError;

use babylon_apis::error::StakingApiError;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Admin(#[from] AdminError),
    #[error("{0}")]
    Std(#[from] StdError),
    #[error("{0}")]
    Payment(#[from] PaymentError),
    #[error("error converting from hex to array: {0}")]
    HexArrayError(#[from] HexToArrayError),
    #[error("{0}")]
    SliceError(#[from] FromSliceError),
    #[error("{0}")]
    StakingError(#[from] StakingApiError),
    #[error("{0}")]
    ProtoError(#[from] DecodeError),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Finality provider already exists: {0}")]
    FinalityProviderAlreadyExists(String),
    #[error("No finality providers are registered in this Consumer")]
    FinalityProviderNotRegistered,
    #[error("Finality provider not found: {0}")]
    FinalityProviderNotFound(String),
    #[error("Staking tx hash already exists: {0}")]
    DelegationAlreadyExists(String),
    #[error("Invalid Btc tx: {0}")]
    InvalidBtcTx(String),
    #[error("Missing unbonding info")]
    MissingUnbondingInfo,
    #[error("Empty unbonding tx")]
    EmptyUnbondingTx,
    #[error("Empty Slashing tx")]
    EmptySlashingTx,
    #[error("Invalid lock type: seconds")]
    ErrInvalidLockType,
    #[error("Invalid lock time blocks: {0}, max: {1}")]
    ErrInvalidLockTime(u32, u32),
    #[error("Empty signature from the delegator")]
    EmptySignature,
    #[error("The finality provider {0} does not have voting power at height {1}")]
    NoVotingPower(String, u64),
    #[error("The chain has not reached the given height yet")]
    HeightTooHigh,
    #[error("The finality provider {0} signed two different blocks at height {1}")]
    DuplicateFinalityVote(String, u64),
}
