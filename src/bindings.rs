//! bindings includes functions that invokes custom messages to Cosmos zone.

use crate::msg::bindings::BabylonMsg;
use cosmwasm_std::{CosmosMsg, Env, Response};

/// try_report_fork_header tries to report a fork to the Cosmos zone
pub fn try_report_fork_header(_env: Env) -> Result<Response<BabylonMsg>, String> {
    // TODO: some verifications?
    // let sender = env.contract.address.into();

    let babylon_msg = BabylonMsg::ForkHeader {
        placeholder: "There is a fork!".to_string(), // TODO: implement me!
    };
    let msg = CosmosMsg::Custom(babylon_msg);

    Ok(Response::new()
        .add_message(msg)
        .add_event(cosmwasm_std::Event::new("Hello from Babylon contract!")) // TODO: remove me
        .add_attribute("method", "try_report_fork_header"))
}

/// try_report_btc_finalized_header tries to report a BTC-finalised header
pub fn try_report_btc_finalized_header(
    _env: Env,
    height: i64,
    time: i64,
) -> Result<Response<BabylonMsg>, String> {
    // TODO: some verifications?
    // let sender = env.contract.address.into();

    let babylon_msg = BabylonMsg::FinalizedHeader { height, time };

    let msg = CosmosMsg::Custom(babylon_msg);

    Ok(Response::new()
        .add_message(msg)
        .add_attribute("method", "try_report_btc_finalized_header"))
}
