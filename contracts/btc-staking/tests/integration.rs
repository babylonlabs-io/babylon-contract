use cosmwasm_std::{ContractResult, Response};
use cosmwasm_vm::testing::{instantiate, mock_env, mock_info, mock_instance};
use cosmwasm_vm::Size;

use btc_staking::msg::InstantiateMsg;

static WASM: &[u8] = include_bytes!("../../../artifacts/btc_staking.wasm");
const MAX_WASM_LEN: Size = Size::kibi(800);

const CREATOR: &str = "creator";

#[test]
fn wasm_size_limit_check() {
    assert!(
        WASM.len() < MAX_WASM_LEN.0,
        "Wasm file too large: {}",
        WASM.len()
    );
}

#[test]
fn instantiate_works() {
    let mut deps = mock_instance(WASM, &[]);

    let msg = InstantiateMsg {
        params: None,
        admin: None,
    };
    let info = mock_info(CREATOR, &[]);
    let res: ContractResult<Response> = instantiate(&mut deps, mock_env(), info, msg);
    let msgs = res.unwrap().messages;
    assert_eq!(0, msgs.len());
}
