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

// TODO: refine error types, e.g., inserting a error msg string
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
    #[error("The BTC header does not satisfy the difficulty requirement or is not consecutive")]
    BTCHeaderError {},
    #[error("The BTC header is not found in the storage")]
    BTCHeaderNotFoundError {},
}
