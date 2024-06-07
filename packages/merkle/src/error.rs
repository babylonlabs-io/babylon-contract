use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum MerkleError {
    #[error("Merkle error: {0}")]
    GenericErr(String),
}

impl MerkleError {
    pub fn generic_err(msg: impl Into<String>) -> Self {
        MerkleError::GenericErr(msg.into())
    }
}
