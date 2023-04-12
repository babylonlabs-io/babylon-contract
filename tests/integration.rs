//! This integration test tries to run and call the generated wasm.
//! It depends on a Wasm build being available, which you can create with `cargo wasm`.
//! Then running `cargo integration-test` will validate we can properly call into that generated Wasm.
//!
//! You can easily convert unit tests to integration tests.
//! 1. First copy them over verbatum,
//! 2. Then change
//!      let mut deps = mock_dependencies(20, &[]);
//!    to
//!      let mut deps = mock_instance(WASM, &[]);
//! 3. If you access raw storage, where ever you see something like:
//!      deps.storage.get(CONFIG_KEY).expect("no data stored");
//!    replace it with:
//!      deps.with_storage(|store| {
//!          let data = store.get(CONFIG_KEY).expect("no data stored");
//!          //...
//!      });
//! 4. Anywhere you see query(&deps, ...) you must replace it with query(&mut deps, ...)
//! TODO: Copy pasting tests here seems a hassle. Can we do something better?

use cosmwasm_std::testing::mock_ibc_channel_open_try;
use cosmwasm_std::{ContractResult, IbcOrder, Response};
use cosmwasm_vm::testing::{
    ibc_channel_open, instantiate, mock_env, mock_info, mock_instance, MockApi, MockQuerier,
    MockStorage,
};
use cosmwasm_vm::Instance;

use babylon_contract::ibc::IBC_APP_VERSION;
use babylon_contract::msg::InstantiateMsg;

// This line will test the output of cargo wasm
// static WASM: &[u8] =
//     include_bytes!("../target/wasm32-unknown-unknown/release/babylon_contract.wasm");
static WASM: &[u8] = include_bytes!("../artifacts/babylon_contract.wasm");

const CREATOR: &str = "creator";

fn setup() -> Instance<MockApi, MockStorage, MockQuerier> {
    let mut deps = mock_instance(WASM, &[]);
    let msg = InstantiateMsg {
        network: babylon_bitcoin::chain_params::Network::Regtest,
        btc_confirmation_depth: 10,
        checkpoint_finalization_timeout: 100,
    };
    let info = mock_info(CREATOR, &[]);
    let res: Response = instantiate(&mut deps, mock_env(), info, msg).unwrap();
    assert_eq!(0, res.messages.len());
    deps
}

#[test]
fn instantiate_works() {
    let mut deps = mock_instance(WASM, &[]);

    let msg = InstantiateMsg {
        network: babylon_bitcoin::chain_params::Network::Regtest,
        btc_confirmation_depth: 10,
        checkpoint_finalization_timeout: 100,
    };
    let info = mock_info("creator", &[]);
    let res: ContractResult<Response> = instantiate(&mut deps, mock_env(), info, msg);
    let msgs = res.unwrap().messages;
    assert_eq!(0, msgs.len());
}

#[test]
fn enforce_version_in_handshake() {
    let mut deps = setup();

    let wrong_order =
        mock_ibc_channel_open_try("channel-1234", IbcOrder::Unordered, IBC_APP_VERSION);
    ibc_channel_open(&mut deps, mock_env(), wrong_order).unwrap_err();

    let wrong_version = mock_ibc_channel_open_try("channel-1234", IbcOrder::Ordered, "reflect");
    ibc_channel_open(&mut deps, mock_env(), wrong_version).unwrap_err();

    let valid_handshake =
        mock_ibc_channel_open_try("channel-1234", IbcOrder::Ordered, IBC_APP_VERSION);
    ibc_channel_open(&mut deps, mock_env(), valid_handshake).unwrap();
}
