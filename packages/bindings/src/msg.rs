//! msg::bindings is the module that includes custom messages that the Babylon contract
//! will send to the Cosmos zone. The messages include:
//! - ForkHeader: reporting a fork that has a valid quorum certificate
//! - FinalizedHeader: reporting a BTC-finalised header.

use babylon_apis::finality_api::Evidence;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Coin, CosmosMsg, Empty};

/// BabylonMsg is the message that the Babylon contract can send to the Cosmos zone.
/// The Cosmos zone has to integrate https://github.com/babylonlabs-io/wasmbinding for
/// handling these messages
#[cw_serde]
pub enum BabylonMsg {
    /// FinalizedHeader reports a BTC-finalised header
    /// can be used for many use cases, notably unbonding mature validators/delegations till this header
    FinalizedHeader {
        height: i64,
        time: i64, // NOTE: UNIX timestamp is in i64
    },
    /// MintRewards mints the requested block rewards for the finality providers.
    /// It can only be sent from the finality contract.
    /// The rewards are minted to the staking contract address, so that they
    /// can be distributed across the active finality provider set
    MintRewards { amount: Coin, recipient: String },
    /// MsgEquivocationEvidence reports the evidence that a finality provider has signed
    /// finality signatures with correct public randomness on two conflicting Babylon headers
    EquivocationEvidence { evidence: Evidence },
}

pub type BabylonSudoMsg = Empty;
pub type BabylonQuery = Empty;

// make BabylonMsg to implement CosmosMsg::CustomMsg
impl cosmwasm_std::CustomMsg for BabylonMsg {}

impl From<BabylonMsg> for CosmosMsg<BabylonMsg> {
    fn from(original: BabylonMsg) -> Self {
        CosmosMsg::Custom(original)
    }
}
