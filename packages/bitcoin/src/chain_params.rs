pub use bitcoin::consensus::Params;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// we re-implement the enum here since `rust-bitcoin`'s enum implementation
// does not have `#[derive(Serialize, Deserialize)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

pub fn get_chain_params(net: Network) -> Params {
    match net {
        Network::Mainnet => Params::new(bitcoin::network::constants::Network::Bitcoin),
        Network::Testnet => Params::new(bitcoin::network::constants::Network::Testnet),
        Network::Signet => Params::new(bitcoin::network::constants::Network::Signet),
        Network::Regtest => Params::new(bitcoin::network::constants::Network::Regtest),
    }
}
