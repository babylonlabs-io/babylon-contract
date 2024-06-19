pub mod btc_staking_api;
pub mod error;
pub mod finality_api;
mod validate;

use cosmwasm_std::{Addr, Binary, CustomQuery, QueryRequest, WasmQuery};

pub fn encode_raw_query<T: Into<Binary>, Q: CustomQuery>(addr: &Addr, key: T) -> QueryRequest<Q> {
    WasmQuery::Raw {
        contract_addr: addr.into(),
        key: key.into(),
    }
    .into()
}

pub type Bytes = Vec<u8>;

pub use validate::Validate;
