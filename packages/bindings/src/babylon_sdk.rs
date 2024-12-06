use anybuf::Bufany;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, QuerierWrapper, StdError, StdResult};

pub const QUERY_PARAMS_PATH: &str = "/babylonlabs/babylon/v1beta1/params";

#[cw_serde]
pub struct QueryParamsResponse {
    pub params: Params,
}

#[cw_serde]
pub struct Params {
    /// babylon_contract_code_id is the code ID of the Babylon contract
    pub babylon_contract_code_id: u64,
    /// btc_staking_contract_code_id is the code ID of the BTC staking contract
    pub btc_staking_contract_code_id: u64,
    /// btc_finality_contract_code_id is the code ID of the BTC finality contract
    pub btc_finality_contract_code_id: u64,
    /// babylon_contract_address is the address of the Babylon contract
    pub babylon_contract_address: Addr,
    /// btc_staking_contract_address is the address of the BTC staking contract
    pub btc_staking_contract_address: Addr,
    /// btc_finality_contract_address is the address of the BTC finality contract
    pub btc_finality_contract_address: Addr,
    /// max_gas_begin_blocker defines the maximum gas that can be spent in a contract sudo callback
    pub max_gas_begin_blocker: u32,
}

impl From<Binary> for QueryParamsResponse {
    fn from(binary: Binary) -> Self {
        let res_decoded = Bufany::deserialize(&binary).unwrap();
        // See https://github.com/babylonlabs-io/babylon/blob/base/consumer-chain-support/proto/babylon/btcstaking/v1/query.proto#L35
        let res_params = res_decoded.message(1).unwrap();
        QueryParamsResponse {
            params: Params {
                babylon_contract_code_id: res_params.uint64(1).unwrap(),
                btc_staking_contract_code_id: res_params.uint64(2).unwrap(),
                btc_finality_contract_code_id: res_params.uint64(3).unwrap(),
                babylon_contract_address: Addr::unchecked(res_params.string(4).unwrap()),
                btc_staking_contract_address: Addr::unchecked(res_params.string(5).unwrap()),
                btc_finality_contract_address: Addr::unchecked(res_params.string(6).unwrap()),
                max_gas_begin_blocker: res_params.uint32(7).unwrap(),
            },
        }
    }
}

pub fn get_babylon_sdk_params(querier: &QuerierWrapper) -> Result<Params, StdError> {
    let params = querier.query_grpc(QUERY_PARAMS_PATH.to_owned(), Binary::new("".into()))?;
    let params = QueryParamsResponse::from(params).params;
    Ok(params)
}
