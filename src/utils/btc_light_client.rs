use crate::error;
use babylon_bitcoin::BlockHeader;
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
        let last_btc_header: BlockHeader =
            babylon_bitcoin::deserialize(last_header.header.as_ref())
                .map_err(|_| error::BTCLightclientError::BTCHeaderDecodeError {})?;
        // decode this header to rust-bitcoin's type
        let btc_header: BlockHeader = babylon_bitcoin::deserialize(new_header.header.as_ref())
            .map_err(|_| error::BTCLightclientError::BTCHeaderDecodeError {})?;

        // validate whether btc_header extends last_btc_header
        babylon_bitcoin::pow::verify_next_header_pow(btc_network, &last_btc_header, &btc_header)
            .map_err(|_| error::BTCLightclientError::BTCHeaderError {})?;

        // this header is good, verify the next one
        last_header = new_header.clone();
    }
    Ok(())
}
