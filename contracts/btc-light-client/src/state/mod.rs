pub mod btc_light_client;
pub mod config;

pub use btc_light_client::{get_base_header, get_header, get_header_by_hash, get_headers, get_tip};
pub use config::{Config, CONFIG};
