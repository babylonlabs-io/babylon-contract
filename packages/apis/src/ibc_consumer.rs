use crate::Bytes;
use cosmwasm_schema::cw_serde;

/// ConsumerPacketData is the message that defines the IBC packets a Consumer can send to Babylon's
/// ZoneConcierge module.
///
/// Defined here as it has to be a JSON-serializable struct
#[cw_serde]
pub struct ConsumerPacketData {
    /// `packet` is the actual message carried in the IBC packet
    pub packet: consumer_packet_data::Packet,
}

/// Nested message and enum types in `ConsumerPacketData`.
pub mod consumer_packet_data {
    use cosmwasm_schema::cw_serde;

    #[cw_serde]
    pub enum Packet {
        Slashing(super::Slashing),
    }
}

/// `Slashing` is the message that defines the slashing information that a Consumer can send to
/// Babylon's ZoneConcierge upon a Consumer slashing event
#[cw_serde]
pub struct Slashing {
    /// `fp_btc_pk` is the BTC PK of the slashed finality provider
    pub fp_btc_pk: Bytes,
    /// `block_height` is the Consumer blockchain slashing height
    pub block_height: u64,
    /// `secret_key` is the secret key extracted from the slashing evidence
    pub secret_key: Bytes,
}
