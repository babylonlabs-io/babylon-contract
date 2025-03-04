use std::str::{from_utf8, FromStr};

use cosmwasm_schema::cw_serde;

use babylon_bitcoin::hash_types::TxMerkleNode;
use babylon_bitcoin::{BlockHash, BlockHeader};
use babylon_proto::babylon::btclightclient::v1::{BtcHeaderInfo, BtcHeaderInfoResponse};

use crate::error::ContractError;

/// Bitcoin header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] committing to all transactions in the block.
///
/// This struct is for use in RPC requests and responses. It has convenience trait impls to convert
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
    pub time: u32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course).
    pub bits: u32,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}

impl BtcHeader {
    pub fn to_btc_header_info(
        &self,
        prev_height: u32,
        prev_work: babylon_bitcoin::Work,
    ) -> Result<BtcHeaderInfo, ContractError> {
        let block_header: BlockHeader = self.try_into()?;
        let total_work = prev_work + block_header.work();
        // To be able to print the decimal repr of the number
        let total_work_cw = cosmwasm_std::Uint256::from_be_bytes(total_work.to_be_bytes());

        Ok(BtcHeaderInfo {
            header: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(&block_header)),
            hash: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(
                &block_header.block_hash(),
            )),
            height: prev_height + 1,
            work: prost::bytes::Bytes::from(total_work_cw.to_string()),
        })
    }
}

/// Try to convert &BtcHeaderInfo to/into BtcHeader
impl TryFrom<&BtcHeaderInfo> for BtcHeader {
    type Error = ContractError;
    fn try_from(btc_header_info: &BtcHeaderInfo) -> Result<Self, Self::Error> {
        let block_header: BlockHeader = babylon_bitcoin::deserialize(&btc_header_info.header)
            .map_err(|_| ContractError::BTCHeaderDecodeError {})?;
        Ok(Self {
            version: block_header.version.to_consensus(),
            prev_blockhash: block_header.prev_blockhash.to_string(),
            merkle_root: block_header.merkle_root.to_string(),
            time: block_header.time,
            bits: block_header.bits.to_consensus(),
            nonce: block_header.nonce,
        })
    }
}

/// Try to convert BtcHeaderInfo to/into BtcHeader
impl TryFrom<BtcHeaderInfo> for BtcHeader {
    type Error = ContractError;
    fn try_from(btc_header_info: BtcHeaderInfo) -> Result<Self, Self::Error> {
        Self::try_from(&btc_header_info)
    }
}

/// Try to convert &BtcHeaderInfoResponse to/into BtcHeader
impl TryFrom<&BtcHeaderInfoResponse> for BtcHeader {
    type Error = ContractError;
    fn try_from(btc_header_info_response: &BtcHeaderInfoResponse) -> Result<Self, Self::Error> {
        let block_header: BlockHeader =
            babylon_bitcoin::deserialize(&hex::decode(&btc_header_info_response.header_hex)?)
                .map_err(|_| ContractError::BTCHeaderDecodeError {})?;
        Ok(Self {
            version: block_header.version.to_consensus(),
            prev_blockhash: block_header.prev_blockhash.to_string(),
            merkle_root: block_header.merkle_root.to_string(),
            time: block_header.time,
            bits: block_header.bits.to_consensus(),
            nonce: block_header.nonce,
        })
    }
}

/// Try to convert BtcHeaderInfoResponse to/into BtcHeader
impl TryFrom<BtcHeaderInfoResponse> for BtcHeader {
    type Error = ContractError;
    fn try_from(btc_header_info_response: BtcHeaderInfoResponse) -> Result<Self, Self::Error> {
        Self::try_from(&btc_header_info_response)
    }
}

/// Try to convert &BtcHeader to/into BlockHeader
impl TryFrom<&BtcHeader> for BlockHeader {
    type Error = ContractError;
    fn try_from(btc_header: &BtcHeader) -> Result<Self, Self::Error> {
        Ok(BlockHeader {
            version: babylon_bitcoin::Version::from_consensus(btc_header.version),
            prev_blockhash: BlockHash::from_str(&btc_header.prev_blockhash)?,
            merkle_root: TxMerkleNode::from_str(&btc_header.merkle_root)?,
            time: btc_header.time,
            bits: babylon_bitcoin::CompactTarget::from_consensus(btc_header.bits),
            nonce: btc_header.nonce,
        })
    }
}

/// Try to convert BtcHeader to/into BlockHeader
impl TryFrom<BtcHeader> for BlockHeader {
    type Error = ContractError;
    fn try_from(btc_header: BtcHeader) -> Result<Self, Self::Error> {
        Self::try_from(&btc_header)
    }
}

/// Response for a BTC header query
#[cw_serde]
pub struct BtcHeaderResponse {
    pub header: BtcHeader,
    pub hash: String,
    pub height: u32,
    pub work: String,
}

impl TryFrom<&BtcHeaderInfo> for BtcHeaderResponse {
    type Error = ContractError;
    fn try_from(btc_header_info: &BtcHeaderInfo) -> Result<Self, Self::Error> {
        let header = BtcHeader::try_from(btc_header_info)?;
        let block_header: BlockHeader = babylon_bitcoin::deserialize(&btc_header_info.header)
            .map_err(|_| ContractError::BTCHeaderDecodeError {})?;
        Ok(Self {
            header,
            hash: block_header.block_hash().to_string(),
            height: btc_header_info.height,
            work: from_utf8(&btc_header_info.work)?.to_string(),
        })
    }
}

/// Response for a BTC headers query
#[cw_serde]
pub struct BtcHeadersResponse {
    pub headers: Vec<BtcHeaderResponse>,
}

impl TryFrom<&[BtcHeaderInfo]> for BtcHeadersResponse {
    type Error = ContractError;
    fn try_from(btc_header_infos: &[BtcHeaderInfo]) -> Result<Self, Self::Error> {
        let headers = btc_header_infos
            .iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { headers })
    }
}
