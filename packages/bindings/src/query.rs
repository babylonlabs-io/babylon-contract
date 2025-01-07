use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{
    from_json, to_json_binary, Addr, ContractResult, QuerierWrapper, StdError, SystemResult,
};

#[cw_serde]
#[derive(QueryResponses)]
pub enum BabylonQuery {
    #[returns(ParamsResponse)]
    Params {},
}

#[cw_serde]
pub struct ParamsResponse {
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

pub fn get_babylon_sdk_params(querier: &QuerierWrapper) -> Result<ParamsResponse, StdError> {
    let query = BabylonQuery::Params {};
    let res = match querier.raw_query(&to_json_binary(&query)?) {
        SystemResult::Err(system_err) => Err(StdError::generic_err(format!(
            "Querier system error: {}",
            system_err
        ))),
        SystemResult::Ok(ContractResult::Err(contract_err)) => Err(StdError::generic_err(format!(
            "Querier contract error: {}",
            contract_err
        ))),
        SystemResult::Ok(ContractResult::Ok(value)) => Ok(value),
    }?;
    let params: ParamsResponse = from_json(&res)?;

    Ok(params)
}
