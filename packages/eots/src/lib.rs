pub mod eots;
pub mod error;

pub use eots::{
    extract, new_pub_rand, new_sec_rand, new_sig, PubRand, PublicKey, SecRand, SecretKey, Signature,
};
pub use error::EotsError;
pub type Result<T> = std::result::Result<T, EotsError>;
