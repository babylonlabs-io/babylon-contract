use babylon_apis::to_canonical_addr;
use cosmos_sdk_proto::ibc::core::channel::v1::{acknowledgement::Response, Acknowledgement};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdError, StdResult};

#[cw_serde]
pub struct IbcIcs20Info {
    pub channel_id: String,
    pub to_address: String,
}

impl IbcIcs20Info {
    pub fn validate(&self) -> StdResult<()> {
        if self.channel_id.is_empty() {
            return Err(StdError::generic_err("Empty IBC channel id"));
        }
        to_canonical_addr(&self.to_address, "bbn")
            .map_err(|e| StdError::generic_err(format!("Invalid recipient address: {}", e)))?;
        Ok(())
    }
}

pub type TransferInfoResponse = Option<IbcIcs20Info>;

pub fn new_ack_res() -> Acknowledgement {
    let resp = Response::Result(vec![]);

    Acknowledgement {
        response: Some(resp),
    }
}

pub fn new_ack_err(emsg: String) -> Acknowledgement {
    let resp = Response::Error(emsg);

    Acknowledgement {
        response: Some(resp),
    }
}

#[cw_serde]
pub struct BtcTimestampResponse {
    pub placeholder: String,
}
