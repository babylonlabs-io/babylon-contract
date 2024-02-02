use crate::error::BTCLightclientError;
use babylon_bitcoin::hash_types::TxMerkleNode;
use babylon_bitcoin::{BlockHash, BlockHeader};
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use cosmwasm_schema::cw_serde;
use std::str::FromStr;

/// Bitcoin header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] committing to all transactions in the block.
///
/// This struct is for use in RPC requests and responses. It has convenience helpers to convert
/// to the internal representation (`BlockHeader`), and to the Babylon extended representation
/// (`BtcHeaderInfo`).
/// Adapted from `BlockHeader`.
#[cw_serde]
pub struct BtcHeader {
    /// Originally protocol version, but repurposed for soft-fork signaling.
    ///
    /// ### Relevant BIPs
    ///
    /// * [BIP9 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
    /// * [BIP34 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
    pub version: i32,
    /// Reference to the previous block in the chain.
    /// Encoded as a (byte-reversed) hex string.
    pub prev_blockhash: String,
    /// The root hash of the merkle tree of transactions in the block.
    /// Encoded as a (byte-reversed) hex string.
    pub merkle_root: String,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course).
    pub bits: u32,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}

impl BtcHeader {
    pub fn to_block_header(&self) -> Result<BlockHeader, BTCLightclientError> {
        Ok(BlockHeader {
            version: self.version,
            prev_blockhash: BlockHash::from_str(&self.prev_blockhash)?,
            merkle_root: TxMerkleNode::from_str(&self.merkle_root)?,
            time: self.time,
            bits: self.bits,
            nonce: self.nonce,
        })
    }

    pub fn to_btc_header_info(
        &self,
        prev_height: u64,
        prev_work: babylon_bitcoin::Uint256,
    ) -> Result<BtcHeaderInfo, BTCLightclientError> {
        let block_header = self.to_block_header()?;
        let total_work = prev_work + block_header.work();
        // To be able to print the decimal repr of the number
        let total_work_cw = cosmwasm_std::Uint256::from_be_bytes(total_work.to_be_bytes());

        Ok(BtcHeaderInfo {
            header: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(&block_header)),
            hash: ::prost::bytes::Bytes::from(block_header.block_hash().to_vec()),
            height: prev_height + 1,
            work: prost::bytes::Bytes::from(total_work_cw.to_string()),
        })
    }
}

/// Convert from `BtcHeader` to `BlockHeader`.
///
/// This is a convenience method to convert from the API representation to the bitcoin representation.
///
/// Note: These from/into methods can panic, and as such, they intended for easing tests and
/// development.
/// In production code, use the `to_block_header()` method, which returns a `Result`.
///
/// Sadly, we can't implement `TryFrom` for `BtcHeader` to `BlockHeader` because of conflicting
/// implementations for `TryFrom` for `BtcHeader` and `Result<BlockHeader, BTCLightclientError>`.
/// This is a known issue in Rust (error[E0119]), and there is no good workaround.
impl From<BtcHeader> for BlockHeader {
    fn from(val: BtcHeader) -> Self {
        val.to_block_header().unwrap()
    }
}

/// Convert from `&BtcHeader` to `BlockHeader`.
///
/// This is a convenience method to convert from the API representation to the bitcoin representation.
///
/// Note: These from/into methods can panic, and as such, they intended for easing tests and
/// development.
/// In production code, use the `to_block_header()` method, which returns a `Result`.
impl From<&BtcHeader> for BlockHeader {
    fn from(val: &BtcHeader) -> Self {
        Self::from(val.clone())
    }
}

/// Convert from `BlockHeader` to/into `BtcHeader`.
impl From<BlockHeader> for BtcHeader {
    fn from(val: BlockHeader) -> Self {
        BtcHeader {
            version: val.version,
            prev_blockhash: val.prev_blockhash.to_string(),
            merkle_root: val.merkle_root.to_string(),
            time: val.time,
            bits: val.bits,
            nonce: val.nonce,
        }
    }
}

/// Convert from `&BlockHeader` to/into `BtcHeader`.
impl From<&BlockHeader> for BtcHeader {
    fn from(val: &BlockHeader) -> Self {
        Self::from(*val)
    }
}

/// Convert from `BtcHeaderInfo` to/into `BtcHeader`.
/// This is a convenience method to convert from the Babylon representation to the API representation.
///
/// Note: This method can panic.
impl From<BtcHeaderInfo> for BtcHeader {
    fn from(val: BtcHeaderInfo) -> Self {
        let block_header: BlockHeader = babylon_bitcoin::deserialize(&val.header).unwrap();
        BtcHeader {
            version: block_header.version,
            prev_blockhash: block_header.prev_blockhash.to_string(),
            merkle_root: block_header.merkle_root.to_string(),
            time: block_header.time,
            bits: block_header.bits,
            nonce: block_header.nonce,
        }
    }
}

/// Convert from `&BtcHeaderInfo` to/into `BtcHeader`.
/// This is a convenience method to convert from the Babylon representation to the API representation.
///
/// Note: This method can panic.
impl From<&BtcHeaderInfo> for BtcHeader {
    fn from(val: &BtcHeaderInfo) -> Self {
        Self::from(val.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btc_header_to_block_header() {
        let btc_header = BtcHeader {
            version: 1,
            prev_blockhash: "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
                .to_string(),
            merkle_root: "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
                .to_string(),
            time: 123,
            bits: 456,
            nonce: 789,
        };
        let block_header = btc_header.to_block_header().unwrap();
        assert_eq!(block_header.version, 1);
        assert_eq!(
            block_header.prev_blockhash.to_string(),
            "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        );
        assert_eq!(
            block_header.merkle_root.to_string(),
            "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
        );
        assert_eq!(block_header.time, 123);
        assert_eq!(block_header.bits, 456);
        assert_eq!(block_header.nonce, 789);
    }

    #[test]
    fn test_btc_header_into_block_header() {
        let btc_header = BtcHeader {
            version: 1,
            prev_blockhash: "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
                .to_string(),
            merkle_root: "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
                .to_string(),
            time: 123,
            bits: 456,
            nonce: 789,
        };
        let block_header: BlockHeader = btc_header.into();
        assert_eq!(block_header.version, 1);
        assert_eq!(
            block_header.prev_blockhash.to_string(),
            "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        );
        assert_eq!(
            block_header.merkle_root.to_string(),
            "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
        );
        assert_eq!(block_header.time, 123);
        assert_eq!(block_header.bits, 456);
        assert_eq!(block_header.nonce, 789);
    }

    #[test]
    fn test_btc_header_to_btc_header_info() {
        // TODO: Use a valid btc header
        let btc_header = BtcHeader {
            version: 1,
            prev_blockhash: "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
                .to_string(),
            merkle_root: "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
                .to_string(),
            time: 123,
            bits: 456,
            nonce: 789,
        };
        let block_header = btc_header.to_block_header().unwrap();
        let btc_header_info = btc_header
            .to_btc_header_info(10, babylon_bitcoin::Uint256::from_u64(23456u64).unwrap());
        assert_eq!(
            btc_header_info,
            Ok(BtcHeaderInfo {
                header: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(&block_header)),
                hash: ::prost::bytes::Bytes::from(block_header.block_hash().to_vec()),
                height: 10 + 1,
                work: ::prost::bytes::Bytes::from("23456".as_bytes()), // header work is zero (invalid block header?)
            })
        );
    }

    #[test]
    fn test_btc_header_from_block_header() {
        let block_header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::from_str(
                "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef",
            )
            .unwrap(),
            merkle_root: TxMerkleNode::from_str(
                "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
            )
            .unwrap(),
            time: 123,
            bits: 456,
            nonce: 789,
        };
        let btc_header = BtcHeader::from(block_header);
        assert_eq!(btc_header.version, 1);
        assert_eq!(
            block_header.prev_blockhash.to_string(),
            "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
        );
        assert_eq!(
            block_header.merkle_root.to_string(),
            "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        );
        assert_eq!(btc_header.time, 123);
        assert_eq!(btc_header.bits, 456);
        assert_eq!(btc_header.nonce, 789);
    }

    #[test]
    fn test_btc_header_from_btc_header_info() {
        let block_header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::from_str(
                "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef",
            )
            .unwrap(),
            merkle_root: TxMerkleNode::from_str(
                "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
            )
            .unwrap(),
            time: 123,
            bits: 456,
            nonce: 789,
        };
        let btc_header_info = BtcHeaderInfo {
            header: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(&block_header)),
            hash: ::prost::bytes::Bytes::from(block_header.block_hash().to_vec()),
            height: 1234,
            work: ::prost::bytes::Bytes::from("5678".as_bytes().to_vec()),
        };
        let btc_header = BtcHeader::from(btc_header_info);
        assert_eq!(btc_header.version, 1);
        assert_eq!(
            btc_header.prev_blockhash,
            block_header.prev_blockhash.to_string()
        );
        assert_eq!(btc_header.merkle_root, block_header.merkle_root.to_string());
        assert_eq!(btc_header.time, 123);
        assert_eq!(btc_header.bits, 456);
        assert_eq!(btc_header.nonce, 789);
    }
}
