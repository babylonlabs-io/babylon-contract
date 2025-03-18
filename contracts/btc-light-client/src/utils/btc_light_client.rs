use crate::error;
use babylon_bitcoin::{BlockHeader, Work};
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use cosmwasm_std::{StdResult, Uint256};
use std::str::{from_utf8, FromStr};

/// verify_headers verifies whether `new_headers` are valid consecutive headers
/// after the given `first_header`
pub fn verify_headers(
    btc_network: &babylon_bitcoin::chain_params::Params,
    first_header: &BtcHeaderInfo,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), error::ContractError> {
    // verify each new header iteratively
    let mut last_header = first_header.clone();
    let mut cum_work_old = total_work(&last_header)?;
    for (i, new_header) in new_headers.iter().enumerate() {
        // decode last header to rust-bitcoin's type
        let last_btc_header: BlockHeader =
            babylon_bitcoin::deserialize(last_header.header.as_ref())
                .map_err(|_| error::ContractError::BTCHeaderDecodeError {})?;
        // decode this header to rust-bitcoin's type
        let btc_header: BlockHeader = babylon_bitcoin::deserialize(new_header.header.as_ref())
            .map_err(|_| error::ContractError::BTCHeaderDecodeError {})?;

        // validate whether btc_header extends last_btc_header
        babylon_bitcoin::pow::verify_next_header_pow(btc_network, &last_btc_header, &btc_header)
            .map_err(|_| error::ContractError::BTCHeaderError {})?;

        let header_work = btc_header.work();
        let cum_work = total_work(new_header)?;

        // Validate cumulative work
        if cum_work_old + header_work != cum_work {
            return Err(error::ContractError::BTCWrongCumulativeWork(
                i,
                cum_work_old + header_work,
                cum_work,
            ));
        }
        cum_work_old = cum_work;
        // Validate height
        if new_header.height != last_header.height + 1 {
            return Err(error::ContractError::BTCWrongHeight(
                i,
                last_header.height + 1,
                new_header.height,
            ));
        }

        // this header is good, verify the next one
        last_header = new_header.clone();
    }
    Ok(())
}

/// Zero work helper / constructor
pub fn zero_work() -> Work {
    Work::from_be_bytes(Uint256::zero().to_be_bytes())
}

/// Returns the total work of the given header.
/// The total work is the cumulative work of the given header and all of its ancestors.
pub fn total_work(header: &BtcHeaderInfo) -> StdResult<Work> {
    // TODO: Use a better encoding (String / binary)
    let header_work = from_utf8(header.work.as_ref())?;
    let header_work_cw = cosmwasm_std::Uint256::from_str(header_work)?;
    Ok(Work::from_be_bytes(header_work_cw.to_be_bytes()))
}
