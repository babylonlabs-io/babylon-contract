pub use bitcoin::consensus::deserialize;
pub use bitcoin::consensus::encode::Error;
pub use bitcoin::BlockHash;
pub use bitcoin::BlockHeader;

pub mod chain_params;
pub mod pow;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_btc_header() {
        // https://babylon.explorers.guru/transaction/8CEC6D605A39378F560C2134ABC931AE7DED0D055A6655B82CC5A31D5DA0BE26
        let btc_header_hex = "00400720b2559c9eb13821d6df53ffab9ddf3a645c559f030cac050000000000000000001ff22ffaa13c41df6aebc4b9b09faf328748c3a45772b6a4c4da319119fd5be3b53a1964817606174cc4c4b0";
        let btc_header_bytes = hex::decode(btc_header_hex).unwrap();
        let _btc_header: BlockHeader = deserialize(&btc_header_bytes).unwrap();
    }
}
