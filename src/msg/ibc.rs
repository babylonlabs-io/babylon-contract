use cosmwasm_schema::cw_serde;
use cosmos_sdk_proto::ibc::core::channel::v1::{Acknowledgement, acknowledgement::Response};

pub fn new_ack_res() -> Acknowledgement {
    let resp = Response::Result(vec![]);
    let ack = Acknowledgement {
        response: Some(resp),
    };
    ack
}

pub fn new_ack_err(emsg: String) -> Acknowledgement {
    let resp = Response::Error(emsg);
    let ack = Acknowledgement {
        response: Some(resp),
    };
    ack
}

#[cw_serde]
pub struct BtcTimestampResponse {
    pub placeholder: String,
}
