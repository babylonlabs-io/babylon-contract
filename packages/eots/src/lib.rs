pub mod eots;
pub mod error;

pub use eots::{extract, PubRand, PublicKey, SecRand, SecretKey, Signature};
pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
