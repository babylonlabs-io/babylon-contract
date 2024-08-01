pub mod eots;
pub mod error;

pub use error::EotsError;
pub type Result<T> = std::result::Result<T, EotsError>;
