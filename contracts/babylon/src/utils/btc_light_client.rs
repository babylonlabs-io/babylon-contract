use crate::error;
use crate::error::BTCLightclientError;
use babylon_bitcoin::BlockHeader;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use cosmwasm_std::{StdResult, Uint256};
use std::str::{from_utf8, FromStr};

/// verify_headers verifies whether `new_headers` are valid consecutive headers
/// after the given `first_header`
pub fn verify_headers(
    btc_network: &babylon_bitcoin::chain_params::Params,
    first_header: &BtcHeaderInfo,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), error::BTCLightclientError> {
    // verify each new header iteratively
    let mut last_header = first_header.clone();
    let mut cum_work_old = total_work(&last_header)?;
    for (i, new_header) in new_headers.iter().enumerate() {
        // decode last header to rust-bitcoin's type
        let last_btc_header: BlockHeader =
            babylon_bitcoin::deserialize(last_header.header.as_ref())
                .map_err(|_| error::BTCLightclientError::BTCHeaderDecodeError {})?;
        // decode this header to rust-bitcoin's type
        let btc_header: BlockHeader = babylon_bitcoin::deserialize(new_header.header.as_ref())
            .map_err(|_| error::BTCLightclientError::BTCHeaderDecodeError {})?;

        // validate whether btc_header extends last_btc_header
        babylon_bitcoin::pow::verify_next_header_pow(btc_network, &last_btc_header, &btc_header)
            .map_err(|_| error::BTCLightclientError::BTCHeaderError {})?;

        let header_work = Uint256::from_be_bytes(btc_header.work().to_be_bytes());
        let cum_work = total_work(new_header)?;

        // Validate cumulative work
        if cum_work_old + header_work != cum_work {
            return Err(BTCLightclientError::BTCWrongCumulativeWork(
                i,
                cum_work_old + header_work,
                cum_work,
                cum_work - cum_work_old - header_work,
            ));
        }
        cum_work_old = cum_work;
        // Validate height
        if new_header.height != last_header.height + 1 {
            return Err(BTCLightclientError::BTCWrongHeight(
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

/// Returns the total work of the given header.
/// The total work is the cumulative work of the given header and all of its ancestors.
pub fn total_work(header: &BtcHeaderInfo) -> StdResult<Uint256> {
    // TODO: Use a better encoding (String / binary)
    let header_work = from_utf8(header.work.as_ref())?;
    Uint256::from_str(header_work)
}
