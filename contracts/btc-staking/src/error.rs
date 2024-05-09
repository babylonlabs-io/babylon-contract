use bitcoin::hashes::FromSliceError;
use bitcoin::hex::HexToArrayError;
use hex::FromHexError;
use thiserror::Error;

use cosmwasm_std::StdError;
use cw_utils::PaymentError;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),
    #[error("{0}")]
    Payment(#[from] PaymentError),
    #[error("{0}")]
    HexError(#[from] FromHexError),
    #[error("error converting from hex to array: {0}")]
    HexArrayError(#[from] HexToArrayError),
    #[error("{0}")]
    SliceError(#[from] FromSliceError),
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
    #[error("Empty Btc public key")]
    EmptyBtcPk,
    #[error("Invalid Btc PK: {0}")]
    InvalidBtcPk(String),
    #[error("Empty proof of possession")]
    MissingPop,
    #[error("Empty master public randomness key")]
    EmptyMasterPubRand,
    #[error("No Finality Providers Btc public keys")]
    EmptyBtcPkList,
    #[error("Duplicate Finality Provider Btc public key: {0}")]
    DuplicatedBtcPk(String),
    #[error("Empty Staking tx")]
    EmptyStakingTx,
    #[error("Empty Slashing tx")]
    EmptySlashingTx,
    #[error("Invalid lock type: seconds")]
    ErrInvalidLockType,
    #[error("Invalid lock time blocks: {0}, max: {1}")]
    ErrInvalidLockTime(u32, u32),
    #[error("Invalid unbonding time blocks: {0}, max: {1}")]
    ErrInvalidUnbondingTime(u32, u32),
    #[error("Empty moniker")]
    EmptyMoniker,
}
