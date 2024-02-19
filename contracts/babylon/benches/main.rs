//! This benchmark tries to run and call the generated wasm.
//! It depends on a Wasm build being available, which you can create by running `cargo optimize` in
//! the workspace root.
//! Then running `cargo bench` will validate we can properly call into that generated Wasm.
//!
use prost::Message;
use std::fs;
use thousands::Separable;

use cosmwasm_std::Response;
use cosmwasm_vm::testing::{
    execute, instantiate, mock_env, mock_info, mock_instance_with_gas_limit,
    mock_instance_with_options, MockApi, MockInstanceOptions, MockQuerier, MockStorage,
};
use cosmwasm_vm::{capabilities_from_csv, Instance};

use babylon_proto::babylon::btclightclient::v1::QueryMainChainResponse;

use babylon_contract::msg::bindings::BabylonMsg;
use babylon_contract::msg::btc_header::BtcHeader;
use babylon_contract::msg::contract::{ExecuteMsg, InstantiateMsg};

// Output of `cargo optimize`
static WASM: &[u8] = include_bytes!("../../../artifacts/babylon_contract.wasm");

// From https://github.com/CosmWasm/wasmd/blob/7ea00e2ea858ed599141e322bd68171998a3259a/x/wasm/types/gas_register.go#L33
const GAS_MULTIPLIER: u64 = 140_000_000;

const CREATOR: &str = "creator";
const TESTDATA_MAIN: &str = "../../testdata/btc_light_client.dat";

#[track_caller]
pub fn setup() -> Instance<MockApi, MockStorage, MockQuerier> {
    let mut deps = mock_instance_with_gas_limit(WASM, 2_250_000_000_000);
    let msg = InstantiateMsg {
        network: babylon_bitcoin::chain_params::Network::Regtest,
        babylon_tag: "01020304".to_string(),
        btc_confirmation_depth: 10,
        checkpoint_finalization_timeout: 99,
        notify_cosmos_zone: false,
    };
    let info = mock_info(CREATOR, &[]);
    let res: Response = instantiate(&mut deps, mock_env(), info, msg).unwrap();
    assert_eq!(0, res.messages.len());
    deps
}

#[track_caller]
pub fn get_main_msg_test_headers() -> Vec<BtcHeader> {
    let testdata: &[u8] = &fs::read(TESTDATA_MAIN).unwrap();
    let res = QueryMainChainResponse::decode(testdata).unwrap();
    res.headers
        .iter()
        .map(TryInto::try_into)
        .collect::<Result<_, _>>()
        .unwrap()
}

fn main() {
    // TODO: Use the `criterion` crate to run benchmarks / track baseline values
    let mut deps = setup();
    let info = mock_info(CREATOR, &[]);
    let env = mock_env();

    let gas_expected = 1_844_838_050_679;

    let gas_before = deps.get_gas_left();

    let test_headers = get_main_msg_test_headers();

    let benchmark_msg = ExecuteMsg::BtcHeaders {
        headers: test_headers.clone(),
    };

    execute::<_, _, _, _, BabylonMsg>(&mut deps, env, info, benchmark_msg).unwrap();

    let gas_used = gas_before - deps.get_gas_left();
    let sdk_gas = gas_used / GAS_MULTIPLIER;

    let headers_len = test_headers.len();
    println!(
        "{} BTC headers call gas    : {}",
        headers_len,
        gas_used.separate_with_underscores()
    );
    println!(
        "{} BTC headers call SDK gas: {}",
        headers_len,
        sdk_gas.separate_with_underscores()
    );
    println!(
        "BTC header avg call gas     : {}",
        (gas_used / headers_len as u64).separate_with_underscores()
    );
    println!(
        "BTC header avg call SDK gas : {}",
        (sdk_gas / headers_len as u64).separate_with_underscores()
    );

    assert!(
        (gas_expected - gas_used as i64).abs() < gas_expected / 10,
        "{} BTC Headers call gas",
        headers_len
    );
}
