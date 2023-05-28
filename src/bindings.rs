//! bindings includes functions that invokes custom messages to Cosmos zone.

use crate::msg::bindings::BabylonMsg;

/// msg_btc_finalized_header returns a message that reports a BTC-finalised header
pub fn msg_btc_finalized_header(height: i64, time: i64) -> BabylonMsg {
    BabylonMsg::FinalizedHeader { height, time }
}
