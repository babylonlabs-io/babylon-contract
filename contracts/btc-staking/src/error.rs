use bitcoin::hashes::FromSliceError;
use bitcoin::hex::HexToArrayError;
use thiserror::Error;

use cosmwasm_std::StdError;
use cw_utils::PaymentError;

use babylon_apis::error::StakingApiError;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
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
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Finality provider already exists: {0}")]
    FinalityProviderAlreadyExists(String),
    #[error("No finality providers are registered in this Consumer")]
    FinalityProviderNotRegistered,
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
}
