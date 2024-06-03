pub mod btc_staking_api;
pub mod error;
pub mod finality_api;
mod validate;

pub type Bytes = Vec<u8>;

pub use validate::Validate;
