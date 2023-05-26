use std::env::current_dir;

use cosmwasm_schema::{export_schema, export_schema_with_title, schema_for, write_api};
use cosmwasm_std::Empty;

use babylon_contract::msg::contract::{ExecuteMsg, InstantiateMsg, QueryMsg};
use babylon_contract::msg::ibc::{BtcTimestampResponse};

fn main() {
    // Clear & write standard API
    write_api! {
        instantiate: InstantiateMsg,
        query: QueryMsg,
        migrate: Empty,
        execute: ExecuteMsg,
    }

    // Schemas for inter-contract communication
    let mut out_dir = current_dir().unwrap();
    out_dir.push("schema");
    // export_schema(&schema_for!(PacketMsg), &out_dir); // TODO: find a way to export schema for IBC packet
    // export_schema_with_title(
    //     &schema_for!(AcknowledgementMsg<BtcTimestampResponse>),
    //     &out_dir,
    //     "AcknowledgementMsgBtcTimestamp",
    // );
}
