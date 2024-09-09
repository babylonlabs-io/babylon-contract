pub mod btc_staking_api;
pub mod error;
pub mod finality_api;
mod validate;

use bech32::{FromBase32, Variant};
use cosmwasm_std::{Addr, Binary, CanonicalAddr, CustomQuery, QueryRequest, WasmQuery};

pub fn encode_raw_query<T: Into<Binary>, Q: CustomQuery>(addr: &Addr, key: T) -> QueryRequest<Q> {
    WasmQuery::Raw {
        contract_addr: addr.into(),
        key: key.into(),
    }
    .into()
}

/// new_canonical_addr converts a bech32 address to a canonical address
/// ported from cosmwasm-std/testing/mock.rs
pub fn new_canonical_addr(addr: &str, prefix: &str) -> Result<CanonicalAddr, StakingApiError> {
    // decode bech32 address
    let decode_result = bech32::decode(addr);
    if let Err(e) = decode_result {
        return Err(StakingApiError::InvalidAddressString(e.to_string()));
    }
    let (decoded_prefix, decoded_data, variant) = decode_result.unwrap();
    // check bech32 prefix
    if decoded_prefix != prefix {
        return Err(StakingApiError::InvalidAddressString(
            "wrong bech32 prefix".to_string(),
        ));
    }
    // check bech32 variant
    if variant == Variant::Bech32m {
        return Err(StakingApiError::InvalidAddressString(
            "wrong bech32 variant".to_string(),
        ));
    }
    // check bech32 data
    let bytes = Vec::<u8>::from_base32(&decoded_data)
        .map_err(|_| StakingApiError::InvalidAddressString("invalid bech32 data".to_string()))?;
    if bytes.len() < 1 || bytes.len() > 255 {
        return Err(StakingApiError::InvalidAddressString(
            "Invalid canonical address length".to_string(),
        ));
    }
    // return canonical address
    Ok(bytes.into())
}

pub type Bytes = Vec<u8>;

use error::StakingApiError;
pub use validate::Validate;
