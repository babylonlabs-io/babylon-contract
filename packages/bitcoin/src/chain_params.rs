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
        Network::Mainnet => Params::new(bitcoin::Network::Bitcoin),
        Network::Testnet => Params::new(bitcoin::Network::Testnet),
        Network::Signet => Params::new(bitcoin::Network::Signet),
        Network::Regtest => Params::new(bitcoin::Network::Regtest),
    }
}

pub fn get_bitcoin_network(net: Network) -> bitcoin::Network {
    match net {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet => bitcoin::Network::Testnet,
        Network::Signet => bitcoin::Network::Signet,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}
