use cosmwasm_schema::cw_serde;

use crate::finality_api::Evidence;

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
    /// `evidence` is the slashing evidence
    pub evidence: Evidence,
}
