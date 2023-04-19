use crate::error;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;

/// verify_headers verifies whether `new_headers` are valid consecutive headers
/// after the given `first_header`
pub fn verify_headers(
    btc_network: &babylon_bitcoin::chain_params::Params,
    first_header: &BtcHeaderInfo,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), error::BTCLightclientError> {
    // verify each new header iteratively
    let mut last_header = first_header.clone();
    for new_header in new_headers.iter() {
        // decode last header to rust-bitcoin's type
        let last_btc_header: babylon_bitcoin::BlockHeader =
            babylon_bitcoin::deserialize(last_header.header.as_ref()).unwrap();
        // decode this header to rust-bitcoin's type
        let btc_header_res: Result<babylon_bitcoin::BlockHeader, babylon_bitcoin::Error> =
            babylon_bitcoin::deserialize(new_header.header.as_ref());
        if btc_header_res.is_err() {
            return Err(error::BTCLightclientError::BTCHeaderDecodeError {});
        }
        let btc_header = btc_header_res.unwrap();

        // validate whether btc_header extends last_btc_header
        let res = babylon_bitcoin::pow::verify_next_header_pow(
            btc_network,
            &last_btc_header,
            &btc_header,
        );
        if res.is_err() {
            return Err(error::BTCLightclientError::BTCHeaderError {});
        }

        // this header is good, verify the next one
        last_header = new_header.clone();
    }
    Ok(())
}
