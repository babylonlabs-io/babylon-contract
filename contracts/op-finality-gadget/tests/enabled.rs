use cosmwasm_std::{from_json, ContractResult, Response};
use cosmwasm_vm::testing::{
    execute, instantiate, mock_env, mock_info, mock_instance, query, MockApi,
};

use op_finality_gadget::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

static WASM: &[u8] = include_bytes!("../../../artifacts/op_finality_gadget.wasm");
const CREATOR: &str = "creator";

#[test]
fn disable_and_reenable_works() {
    // Setup
    let mut instance = mock_instance(WASM, &[]);
    let mock_api = MockApi::default();
    let msg = InstantiateMsg {
        admin: mock_api.addr_make(CREATOR),
        consumer_id: "op-stack-l2-11155420".to_string(),
        is_enabled: false,
    };
    let info = mock_info(CREATOR, &[]);
    let mut res: ContractResult<Response> =
        instantiate(&mut instance, mock_env(), info, msg.clone());
    assert!(res.is_ok());

    // Check the contract is disabled on instantiation
    let mut enabled: bool =
        from_json(query(&mut instance, mock_env(), QueryMsg::IsEnabled {}).unwrap()).unwrap();
    assert!(!enabled, "Contract should be disabled on instantiation");

    // Enable the contract
    let info = mock_info(&mock_api.addr_make(CREATOR), &[]);
    res = execute(
        &mut instance,
        mock_env(),
        info,
        ExecuteMsg::SetEnabled { enabled: true },
    );
    assert!(res.is_ok());
    enabled = from_json(query(&mut instance, mock_env(), QueryMsg::IsEnabled {}).unwrap()).unwrap();
    assert!(enabled, "Enabling works");

    // Disable the contract
    let info = mock_info(&mock_api.addr_make(CREATOR), &[]);
    res = execute(
        &mut instance,
        mock_env(),
        info,
        ExecuteMsg::SetEnabled { enabled: false },
    );
    assert!(res.is_ok());
    enabled = from_json(query(&mut instance, mock_env(), QueryMsg::IsEnabled {}).unwrap()).unwrap();
    assert!(!enabled, "Disabling works");

    // Re-enable the contract
    // This simulates a scenario where the contract is disabled for e.g. to fix a bug, and then
    // subsequently re-enabled after a fix is deployed.
    let info = mock_info(&mock_api.addr_make(CREATOR), &[]);
    res = execute(
        &mut instance,
        mock_env(),
        info,
        ExecuteMsg::SetEnabled { enabled: true },
    );
    assert!(res.is_ok());
    enabled = from_json(query(&mut instance, mock_env(), QueryMsg::IsEnabled {}).unwrap()).unwrap();
    assert!(enabled, "Re-enabling works");
}

#[test]
fn instantiate_enabled() {
    // Setup
    let mut instance = mock_instance(WASM, &[]);
    let mock_api = MockApi::default();
    let msg = InstantiateMsg {
        admin: mock_api.addr_make(CREATOR),
        consumer_id: "op-stack-l2-11155420".to_string(),
        is_enabled: true,
    };
    let info = mock_info(CREATOR, &[]);
    let res: ContractResult<Response> = instantiate(&mut instance, mock_env(), info, msg.clone());
    assert!(res.is_ok());

    // Check the contract is disabled on instantiation
    let enabled: bool =
        from_json(query(&mut instance, mock_env(), QueryMsg::IsEnabled {}).unwrap()).unwrap();
    assert!(enabled, "Contract should be enabled on instantiation");
}
