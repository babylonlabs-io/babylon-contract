use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    StdError(#[from] StdError),
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
    #[error("The bytes cannot be decoded")]
    DecodeError(#[from] prost::DecodeError),
    #[error("The BTC header cannot be decoded")]
    BTCHeaderDecodeError {},
    #[error("The BTC header is not being sent")]
    BTCHeaderEmpty {},
    #[error("The BTC header does not satisfy the difficulty requirement or is not consecutive")]
    BTCHeaderError {},
    #[error("The BTC header with hash {hash} is not found in the storage")]
    BTCHeaderNotFoundError { hash: String },
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
