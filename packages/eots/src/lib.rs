pub mod eots;
pub mod error;

pub use eots::{tagged_hash, PubRand, PublicKey, SecRand, SecretKey, Signature, CHALLENGE_TAG};
pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
