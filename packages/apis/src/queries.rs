use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    to_json_vec, Binary, ContractResult, CustomQuery, GrpcQuery, QuerierWrapper, QueryRequest,
    StdError, StdResult, SystemResult,
};

use crate::btcstk_consumer_api::FinalityProviderResponse;

use anybuf::{Anybuf, Bufany};

#[cw_serde]
pub struct BabylonQueryWrapper {}

impl CustomQuery for BabylonQueryWrapper {}

pub struct BabylonQuerier<'a> {
    querier: &'a QuerierWrapper<'a, BabylonQueryWrapper>,
}

// TODO: query_grpc need to be replaced with cosmwasm::std::QuerierWrapper.query_grpc
impl<'a> BabylonQuerier<'a> {
    pub fn new(querier: &'a QuerierWrapper<BabylonQueryWrapper>) -> Self {
        BabylonQuerier { querier }
    }

    // btcstkconsumer
    pub fn query_finality_provider(
        &self,
        consumer_id: String,
        fp_btc_pk_hex: String,
    ) -> StdResult<FinalityProviderResponse> {
        let query_data = Anybuf::new()
            .append_string(1, consumer_id.clone())
            .append_string(2, fp_btc_pk_hex.clone())
            .into_vec();

        let res_data: Binary = self.query_grpc(
            "/babylon.btcstkconsumer.v1.Query/FinalityProvider".to_string(),
            Binary::new(query_data),
        )?;

        let res_decoded = Bufany::deserialize(&res_data).unwrap();
        let res_fp = res_decoded.message(1).unwrap();
        // see https://github.com/babylonchain/babylon-private/blob/base/consumer-chain-support/proto/babylon/btcstkconsumer/v1/query.proto#L116
        // to understand how the index is determined here i.e. 6-10
        let res: FinalityProviderResponse = FinalityProviderResponse {
            slashed_babylon_height: res_fp.uint64(6).unwrap(),
            slashed_btc_height: res_fp.uint64(7).unwrap(),
            height: res_fp.uint64(8).unwrap(),
            voting_power: res_fp.uint64(9).unwrap(),
            consumer_id: res_fp.string(10).unwrap(),
        };

        Ok(res)
    }

    /// copy from the cosmwasm
    /// See [`GrpcQuery`](crate::GrpcQuery) for more information.
    pub fn query_grpc(&self, path: String, data: Binary) -> StdResult<Binary> {
        self.query_raw(&QueryRequest::<BabylonQueryWrapper>::Grpc(GrpcQuery {
            path,
            data,
        }))
    }

    /// copy from the cosmwasm
    /// Internal helper to avoid code duplication.
    /// Performs a query and returns the binary result without deserializing it,
    /// wrapping any errors that may occur into `StdError`.
    fn query_raw(&self, request: &QueryRequest<BabylonQueryWrapper>) -> StdResult<Binary> {
        let raw = to_json_vec(request).map_err(|serialize_err| {
            StdError::generic_err(format!("Serializing QueryRequest: {serialize_err}"))
        })?;
        match self.querier.raw_query(&raw) {
            SystemResult::Err(system_err) => Err(StdError::generic_err(format!(
                "Querier system error: {system_err}"
            ))),
            SystemResult::Ok(ContractResult::Err(contract_err)) => Err(StdError::generic_err(
                format!("Querier contract error: {contract_err}"),
            )),
            SystemResult::Ok(ContractResult::Ok(value)) => Ok(value),
        }
    }
}
