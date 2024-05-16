use babylon_bitcoin::Work;
use cosmwasm_std::StdError;
use cw_utils::ParseReplyError;
use hex::FromHexError;
use prost::DecodeError;
use std::str::Utf8Error;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("{0}")]
    ParseReply(#[from] ParseReplyError),
    #[error("Invalid reply id: {0}")]
    InvalidReplyId(u64),
    #[error("{0}")]
    BtcError(#[from] BTCLightclientError),
    #[error("{0}")]
    BabylonEpochError(#[from] BabylonEpochChainError),
    #[error("{0}")]
    CzHeaderError(#[from] CZHeaderChainError),
    #[error("The contract only supports ordered channels")]
    IbcUnorderedChannel {},
    #[error("Counterparty version must be `{version}`")]
    IbcInvalidCounterPartyVersion { version: String },
    #[error("IBC method is not supported")]
    IbcUnsupportedMethod {},
}

#[derive(Error, Debug, PartialEq)]
pub enum CZHeaderChainError {
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("The given headers during initialization cannot be verified")]
    InitError {},
    #[error("The bytes cannot be decoded")]
    DecodeError(#[from] prost::DecodeError),
    #[error("The header is not checkpointed in the given epoch")]
    EpochNumberError {},
    #[error("The Proof cannot be verified")]
    ProofError {},
    #[error("The CZ header cannot be decoded")]
    CZHeaderDecodeError {},
    #[error("The CZ header with height {height} is not found in the storage")]
    CZHeaderNotFoundError { height: u64 },
    #[error("There is no finalized CZ header yet")]
    NoCZHeader {},
}

#[derive(Error, Debug, PartialEq)]
pub enum BTCLightclientError {
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("The given headers during initialization cannot be verified")]
    InitError {},
    #[error("The given headers during initialization cannot be verified. Less than {0} headers")]
    InitErrorLength(u64),
    #[error("The bytes cannot be decoded")]
    DecodeError(#[from] DecodeError),
    #[error("{0}")]
    HashError(#[from] babylon_bitcoin::HexError),
    #[error("The hex cannot be decoded")]
    DecodeHexError(#[from] FromHexError),
    #[error("The bytes cannot be decoded as string")]
    DecodeUtf8Error(#[from] Utf8Error),
    #[error("The BTC header cannot be decoded")]
    BTCHeaderDecodeError {},
    #[error("The BTC header cannot be encoded")]
    BTCHeaderEncodeError {},
    #[error("The BTC header is not being sent")]
    BTCHeaderEmpty {},
    #[error("The BTC header does not satisfy the difficulty requirement or is not consecutive")]
    BTCHeaderError {},
    #[error("The BTC header with height {height} is not found in the storage")]
    BTCHeaderNotFoundError { height: u64 },
    #[error("The BTC height with hash {hash} is not found in the storage")]
    BTCHeightNotFoundError { hash: String },
    #[error("The BTC header info cumulative work encoding is wrong")]
    BTCWrongCumulativeWorkEncoding {},
    #[error("The BTC header info {0} cumulative work is wrong. Expected {1}, got {2}")]
    BTCWrongCumulativeWork(usize, Work, Work),
    #[error("The BTC header info {0} height is wrong. Expected {1}, got {2}")]
    BTCWrongHeight(usize, u64, u64),
    #[error("The new chain's work ({0}), is not better than the current chain's work ({1})")]
    BTCChainWithNotEnoughWork(Work, Work),
}

#[derive(Error, Debug, PartialEq)]
pub enum BabylonEpochChainError {
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("The bytes cannot be decoded")]
    DecodeError(#[from] prost::DecodeError),
    #[error("Bitcoin light client error: {0}")]
    BTCLightClientError(#[from] BTCLightclientError),
    #[error("The epoch {epoch_number} is not found in the storage")]
    EpochNotFoundError { epoch_number: u64 },
    #[error("There is no finalized epoch yet")]
    NoFinalizedEpoch {},
    #[error(
        "The checkpoint is for epoch {ckpt_epoch_number} rather than the given epoch {epoch_number}"
    )]
    CheckpointNotMatchError {
        ckpt_epoch_number: u64,
        epoch_number: u64,
    },
    #[error("The checkpoint of epoch {epoch_number} is not found in the storage")]
    CheckpointNotFoundError { epoch_number: u64 },
    #[error("The BTC header with hash {hash} is not found in the storage")]
    BTCHeaderNotFoundError { hash: String },
    #[error("The BTC headers are not {w}-deep")]
    BTCHeaderNotDeepEnough { w: u64 },
    #[error("The checkpoint is not in the given BTC headers: {err_msg}")]
    CheckpointNotSubmitted { err_msg: String },
    #[error("The epoch is not sealed by the epoch's validator set: {err_msg}")]
    EpochNotSealed { err_msg: String },
    #[error("Transaction key is empty")]
    EmptyTxKey {},
    #[error("The BTC header cannot be decoded")]
    BTCHeaderDecodeError {},
}
