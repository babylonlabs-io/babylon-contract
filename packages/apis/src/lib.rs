pub mod btc_staking_api;
pub mod error;
pub mod finality_api;
mod validate;

use cosmwasm_std::testing::MockApi;
use cosmwasm_std::{Addr, Api, Binary, CanonicalAddr, CustomQuery, QueryRequest, WasmQuery};

pub fn encode_raw_query<T: Into<Binary>, Q: CustomQuery>(addr: &Addr, key: T) -> QueryRequest<Q> {
    WasmQuery::Raw {
        contract_addr: addr.into(),
        key: key.into(),
    }
    .into()
}
pub fn new_canonical_addr(addr: &str, prefix: &str) -> Result<CanonicalAddr, StakingApiError> {
    let p: &'static str = Box::leak(prefix.to_string().into_boxed_str());
    let api = MockApi::default().with_prefix(p);
    let canonical_addr = api.addr_canonicalize(addr)?;
    Ok(canonical_addr)
}

pub type Bytes = Vec<u8>;

use error::StakingApiError;
pub use validate::Validate;
