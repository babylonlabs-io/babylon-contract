use anybuf::{Anybuf, Bufany};
use cosmwasm_std::{Binary, Deps, StdResult};

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

    let res_data: Binary = deps.querier.query_grpc(
        "/babylon.btcstkconsumer.v1.Query/FinalityProvider".to_string(),
        Binary::new(query_data),
    )?;

    let res_decoded = Bufany::deserialize(&res_data).unwrap();
    // see https://github.com/babylonlabs-io/babylon/blob/base/consumer-chain-support/proto/babylon/btcstkconsumer/v1/query.proto#L110
    let res_fp = res_decoded.message(1).unwrap();
    // see https://github.com/babylonlabs-io/babylon/blob/base/consumer-chain-support/proto/babylon/btcstkconsumer/v1/query.proto#L116
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
