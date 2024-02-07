use crate::error::CZHeaderChainError;
use babylon_proto::babylon::zoneconcierge::v1::IndexedHeader;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Timestamp;

/// CzHeaderResponse is the metadata of a CZ header.
///
/// This struct is for use in RPC requests and responses. It has convenience helpers to convert
/// from the internal representation (`IndexedHeader`).
///
/// Adapted from `IndexedHeader`.
#[cw_serde]
pub struct CzHeaderResponse {
    /// chain_id is the unique ID of the chain
    pub chain_id: String,
    /// hash is the hash of this header.
    /// Hex-encoded string of 32 bytes
    pub hash: String,
    /// height is the height of this header in the CZ ledger.
    /// (hash, height) jointly provides the position of the header on CZ ledger
    pub height: u64,
    /// time is the timestamp of this header in the CZ ledger.
    /// It is needed for the CZ to unbond all mature validators/delegations before this timestamp
    /// when this header is BTC-finalised
    pub time: Option<Timestamp>,
    /// babylon_header_hash is the hash of the babylon block that includes this CZ
    /// header
    /// Hex-encoded string of 32 bytes
    pub babylon_header_hash: String,
    /// babylon_header_height is the height of the babylon block that includes this CZ
    /// header
    pub babylon_header_height: u64,
    /// epoch is the epoch number of this header in the Babylon ledger
    pub babylon_epoch: u64,
    /// babylon_tx_hash is the hash of the tx that includes this header.
    /// (babylon_block_height, babylon_tx_hash) jointly provides the position of
    /// the header in the Babylon ledger.
    /// Hex-encoded string of 32 bytes
    pub babylon_tx_hash: String,
}

impl TryFrom<&IndexedHeader> for CzHeaderResponse {
    type Error = CZHeaderChainError;

    /// Convert from `&IndexedHeader` to `CzHeaderResponse`.
    fn try_from(header: &IndexedHeader) -> Result<Self, Self::Error> {
        Ok(CzHeaderResponse {
            chain_id: header.chain_id.clone(),
            hash: hex::encode(&header.hash),
            height: header.height,
            time: header
                .time
                .as_ref()
                .map(|t| Timestamp::from_seconds(t.seconds as u64).plus_nanos(t.nanos as u64)),
            babylon_header_hash: hex::encode(&header.babylon_header_hash),
            babylon_header_height: header.babylon_header_height,
            babylon_epoch: header.babylon_epoch,
            babylon_tx_hash: hex::encode(&header.babylon_tx_hash),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_header_to_indexed_header_response_works() {
        let indexed_header = IndexedHeader {
            chain_id: "chain_id".to_string(),
            hash: prost::bytes::Bytes::from("hash"),
            height: 1,
            time: Some(::pbjson_types::Timestamp {
                seconds: 2,
                nanos: 3,
            }),
            babylon_header_hash: prost::bytes::Bytes::from("babylon_header_hash"),
            babylon_header_height: 4,
            babylon_epoch: 5,
            babylon_tx_hash: prost::bytes::Bytes::from("babylon_tx_hash"),
        };

        let indexed_header_response = CzHeaderResponse::try_from(&indexed_header).unwrap();

        assert_eq!(indexed_header_response.chain_id, "chain_id");
        assert_eq!(indexed_header_response.hash, hex::encode("hash"));
        assert_eq!(indexed_header_response.height, 1);
        assert_eq!(
            indexed_header_response.time.unwrap(),
            Timestamp::from_seconds(2).plus_nanos(3)
        );
        assert_eq!(
            indexed_header_response.babylon_header_hash,
            hex::encode("babylon_header_hash")
        );
        assert_eq!(indexed_header_response.babylon_header_height, 4);
        assert_eq!(indexed_header_response.babylon_epoch, 5);
        assert_eq!(
            indexed_header_response.babylon_tx_hash,
            hex::encode("babylon_tx_hash")
        );
    }
}
