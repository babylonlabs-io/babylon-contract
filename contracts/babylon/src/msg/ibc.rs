use crate::ibc::TransferInfo;
use babylon_apis::to_canonical_addr;
use cosmos_sdk_proto::ibc::core::channel::v1::{acknowledgement::Response, Acknowledgement};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdError, StdResult};

#[cw_serde]
pub struct IbcTransferInfo {
    pub channel_id: String,
    pub recipient: Recipient,
}

#[cw_serde]
pub enum Recipient {
    ContractAddr(String),
    ModuleAddr(String),
}

impl IbcTransferInfo {
    pub fn validate(&self) -> StdResult<()> {
        if self.channel_id.is_empty() {
            return Err(StdError::generic_err("Empty IBC channel id"));
        }
        match self.recipient {
            Recipient::ContractAddr(ref addr) => {
                to_canonical_addr(addr, "bbn").map_err(|e| {
                    StdError::generic_err(format!("Invalid contract address: {}", e))
                })?;
            }
            Recipient::ModuleAddr(ref addr) => {
                if addr.is_empty() {
                    return Err(StdError::generic_err("Empty module address"));
                }
            }
        }
        Ok(())
    }
}

pub type TransferInfoResponse = Option<TransferInfo>;

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
