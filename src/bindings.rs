//! bindings includes functions that invokes custom messages to Cosmos zone.

use crate::msg::bindings::BabylonMsg;
use babylon_proto::babylon::zoneconcierge::v1::IndexedHeader;
use cosmwasm_std::StdError;

/// msg_btc_finalized_header returns a message that reports a BTC-finalised header
/// from a given IndexedHeader
pub fn msg_btc_finalized_header(cz_header: &IndexedHeader) -> Result<BabylonMsg, StdError> {
    let height = cz_header.height as i64;
    let time = cz_header
        .time
        .as_ref()
        .ok_or(StdError::generic_err("empty time"))?
        .seconds;
    Ok(BabylonMsg::FinalizedHeader { height, time })
}
