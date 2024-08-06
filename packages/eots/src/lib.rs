pub mod eots;
pub mod error;

pub use eots::{PubRand, PublicKey, SecRand, SecretKey, Signature};
pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
