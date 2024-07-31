use anybuf::{Anybuf, Bufany};
use cosmwasm_std::{
    to_json_vec, Binary, ContractResult, Deps, GrpcQuery, QueryRequest, StdError, StdResult,
    SystemResult,
};

/// FinalityProviderResponse defines a finality provider with voting power information.
pub struct FinalityProviderResponse {
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    pub slashed_btc_height: u64,
    /// height is the queried Babylon height
    pub height: u64,
    /// voting_power is the voting power of this finality provider at the given height
    pub voting_power: u64,
    /// consumer_id is the consumer id this finality provider is registered to
    pub consumer_id: String,
}

pub fn query_finality_provider(
    deps: Deps,
    consumer_id: String,
    fp_btc_pk_hex: String,
) -> StdResult<FinalityProviderResponse> {
    let query_data = Anybuf::new()
        .append_string(1, consumer_id.clone())
        .append_string(2, fp_btc_pk_hex.clone())
        .into_vec();

    let res_data: Binary = query_grpc(
        deps,
        "/babylon.btcstkconsumer.v1.Query/FinalityProvider".to_string(),
        Binary::new(query_data),
    )?;

    let res_decoded = Bufany::deserialize(&res_data).unwrap();
    // see https://github.com/babylonlabs-io/babylon-private/blob/base/consumer-chain-support/proto/babylon/btcstkconsumer/v1/query.proto#L110
    let res_fp = res_decoded.message(1).unwrap();
    // see https://github.com/babylonlabs-io/babylon-private/blob/base/consumer-chain-support/proto/babylon/btcstkconsumer/v1/query.proto#L116
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

/// TODO: query_grpc need to be replaced with cosmwasm::std::QuerierWrapper.query_grpc
/// copy from the cosmwasm
/// See [`GrpcQuery`](crate::GrpcQuery) for more information.
pub fn query_grpc(deps: Deps, path: String, data: Binary) -> StdResult<Binary> {
    query_raw(deps, &QueryRequest::Grpc(GrpcQuery { path, data }))
}

/// copy from the cosmwasm
/// Internal helper to avoid code duplication.
/// Performs a query and returns the binary result without deserializing it,
/// wrapping any errors that may occur into `StdError`.
fn query_raw(deps: Deps, request: &QueryRequest<GrpcQuery>) -> StdResult<Binary> {
    let raw = to_json_vec(request).map_err(|serialize_err| {
        StdError::generic_err(format!("Serializing QueryRequest: {serialize_err}"))
    })?;
    match deps.querier.raw_query(&raw) {
        SystemResult::Err(system_err) => Err(StdError::generic_err(format!(
            "Querier system error: {system_err}"
        ))),
        SystemResult::Ok(ContractResult::Err(contract_err)) => Err(StdError::generic_err(format!(
            "Querier contract error: {contract_err}"
        ))),
        SystemResult::Ok(ContractResult::Ok(value)) => Ok(value),
    }
}
