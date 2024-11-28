use cosmwasm_std::{from_json, ContractResult, Response};
use cosmwasm_vm::testing::{instantiate, mock_env, mock_info, mock_instance, query, MockApi};

use cw_controllers::AdminResponse;
use op_finality_gadget::msg::{InstantiateMsg, QueryMsg};
use op_finality_gadget::state::config::Config;

static WASM: &[u8] = include_bytes!("../../../artifacts/op_finality_gadget.wasm");
const CREATOR: &str = "creator";

#[test]
fn instantiate_works() {
    // Setup
    let mut deps = mock_instance(WASM, &[]);
    let mock_api: MockApi = MockApi::default();
    let msg = InstantiateMsg {
        admin: mock_api.addr_make(CREATOR),
        consumer_id: "op-stack-l2-11155420".to_string(),
        is_enabled: false,
    };
    let info = mock_info(CREATOR, &[]);
    let res: ContractResult<Response> = instantiate(&mut deps, mock_env(), info, msg.clone());
    let msgs = res.unwrap().messages;
    assert_eq!(0, msgs.len());

    // Check the config is properly stored in the state and returned
    let res: Config =
        from_json(query(&mut deps, mock_env(), QueryMsg::Config {}).unwrap()).unwrap();
    assert_eq!(msg.consumer_id, res.consumer_id);

    // Check the admin is properly stored in the state and returned
    let res: AdminResponse =
        from_json(query(&mut deps, mock_env(), QueryMsg::Admin {}).unwrap()).unwrap();
    assert_eq!(mock_api.addr_make(CREATOR), res.admin.unwrap());

    // Check the contract is disabled on instantiation
    let enabled: bool =
        from_json(query(&mut deps, mock_env(), QueryMsg::IsEnabled {}).unwrap()).unwrap();
    assert!(!enabled);

    // Check the forked blocks array is empty on instantiation
    let forked_blocks: Vec<(u64, u64)> =
        from_json(query(&mut deps, mock_env(), QueryMsg::ForkedBlocks {}).unwrap()).unwrap();
    assert_eq!(0, forked_blocks.len());
}
