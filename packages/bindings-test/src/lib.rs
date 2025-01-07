mod multitest;

use std::marker::PhantomData;

use babylon_bindings::query::{BabylonQuery, ParamsResponse};
use cosmwasm_std::{
    testing::{MockApi, MockQuerier, MockStorage},
    to_json_binary, Addr, ContractResult, OwnedDeps, SystemResult,
};
pub use multitest::{
    mock_deps_babylon, BabylonApp, BabylonAppWrapped, BabylonDeps, BabylonError, BabylonModule,
    BLOCK_TIME,
};

pub fn mock_dependencies(
) -> OwnedDeps<MockStorage, MockApi, MockQuerier<BabylonQuery>, BabylonQuery> {
    let custom_querier: MockQuerier<BabylonQuery> = MockQuerier::new(&[("", &[])])
        .with_custom_handler(|query| {
            // Handle your custom query type here
            match query {
                BabylonQuery::Params {} => {
                    // Return a mock response for the custom query
                    let response = ParamsResponse {
                        babylon_contract_address: Addr::unchecked(""),
                        btc_staking_contract_address: Addr::unchecked(""),
                        btc_finality_contract_address: Addr::unchecked(""),
                        babylon_contract_code_id: 0,
                        btc_staking_contract_code_id: 0,
                        btc_finality_contract_code_id: 0,
                        max_gas_begin_blocker: 0,
                    };
                    SystemResult::Ok(ContractResult::Ok(to_json_binary(&response).unwrap()))
                }
                _ => panic!("Unsupported query type"),
            }
        });
    OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: custom_querier,
        custom_query_type: PhantomData,
    }
}
