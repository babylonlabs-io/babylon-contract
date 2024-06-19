use cosmwasm_std::{from_json, ContractResult, Response};
use cosmwasm_vm::testing::{instantiate, mock_env, mock_info, mock_instance, query, MockApi};

use op_finality_gadget::msg::{InstantiateMsg, QueryMsg};
use op_finality_gadget::state::config::Config;

static WASM: &[u8] = include_bytes!("../../../artifacts/op_finality_gadget.wasm");
const CREATOR: &str = "creator";

#[test]
fn instantiate_works() {
    let mut deps = mock_instance(WASM, &[]);
    let mock_api = MockApi::default();
    let admin_addr = mock_api.addr_make(CREATOR);
    let env = mock_env();
    let msg = InstantiateMsg {
        admin: admin_addr,
        consumer_id: "op-stack-l2-11155420".to_string(),
        activated_height: 13513311,
    };
    let info = mock_info(CREATOR, &[]);
    let res: ContractResult<Response> = instantiate(&mut deps, mock_env(), info, msg.clone());
    let msgs = res.unwrap().messages;
    assert_eq!(0, msgs.len());

    // check the config is properly stored in the state and returned
    let res: Config = from_json(query(&mut deps, env, QueryMsg::Config {}).unwrap()).unwrap();
    assert_eq!(msg.consumer_id, res.consumer_id);
    assert_eq!(msg.activated_height, res.activated_height);
}
