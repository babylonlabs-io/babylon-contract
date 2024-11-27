use cosmwasm_std::{from_json, ContractResult, Response};
use cosmwasm_vm::testing::{
    execute, instantiate, mock_env, mock_info, mock_instance, query, MockApi,
};

use op_finality_gadget::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

static WASM: &[u8] = include_bytes!("../../../artifacts/op_finality_gadget.wasm");
const CREATOR: &str = "creator";

// Test cases:
// 1. Success case: checking is block forked returns false for empty forked blocks array
// 2. Success case: checking is block forked in forked block range returns true
// 3. Success case: checking is block forked outside (after) forked block range returns false
// 4. Success case: checking is block forked outside (before) forked block range returns false
// 5. Success case: checking forked blocks in range returns empty list for non-overlapping block range
// 6. Success case: checking forked blocks in range returns list of forked blocks for single overlapping block range
// 7. Success case: checking forked blocks in range returns list of forked blocks for multiple overlapping block ranges
// 8. Fail case: Non-admin caller cannot whitelist forked blocks

#[test]
fn no_forked_blocks() {
    test_forked_block_helper(vec![], 1, false, "no forked blocks");
}

#[test]
fn forked_block_in_range_start() {
    test_forked_block_helper(vec![(1, 10)], 1, true, "forked block in range");
}

#[test]
fn forked_block_in_range_middle() {
    test_forked_block_helper(vec![(1, 10)], 5, true, "forked block in range");
}

#[test]
fn forked_block_in_range_end() {
    test_forked_block_helper(vec![(1, 10)], 10, true, "forked block in range");
}

#[test]
fn forked_blocks_in_range_non_overlapping() {
    test_forked_block_range_helper(
        vec![(1, 10), (15, 20)],
        13,
        14,
        vec![],
        "block ranges not overlapping",
    );
}

#[test]
fn forked_blocks_in_range_single_overlapping() {
    test_forked_block_range_helper(
        vec![(1, 10), (15, 20)],
        6,
        12,
        vec![(6, 10)],
        "single overlapping block range",
    );
}

#[test]
fn forked_blocks_in_range_multiple_overlapping() {
    test_forked_block_range_helper(
        vec![(1, 10), (15, 20)],
        6,
        17,
        vec![(6, 10), (15, 17)],
        "multiple overlapping block ranges",
    );
}

#[test]
#[should_panic(expected = "Empty block range")]
fn whitelist_empty_block_range() {
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

    // Add forked block as admin caller
    let info = mock_info(&mock_api.addr_make(CREATOR), &[]);
    let res: ContractResult<Response> = execute(
        &mut instance,
        mock_env(),
        info,
        ExecuteMsg::WhitelistForkedBlocks {
            forked_blocks: vec![],
        },
    );
    res.unwrap();
}

#[test]
#[should_panic(expected = "Caller is not the admin")]
fn whitelist_non_admin_caller() {
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

    // Add forked block as admin caller
    let caller = mock_api.addr_make("caller");
    let info = mock_info(&caller, &[]);
    let res: ContractResult<Response> = execute(
        &mut instance,
        mock_env(),
        info,
        ExecuteMsg::WhitelistForkedBlocks {
            forked_blocks: vec![(1, 10)],
        },
    );
    res.unwrap();
}

// Helper functions

fn test_forked_block_helper(
    whitelist_blocks: Vec<(u64, u64)>,
    query_height: u64,
    exp_is_forked: bool,
    exp_msg: &str,
) {
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

    // Add forked block as admin caller
    if !whitelist_blocks.is_empty() {
        let info = mock_info(&mock_api.addr_make(CREATOR), &[]);
        let res: ContractResult<Response> = execute(
            &mut instance,
            mock_env(),
            info,
            ExecuteMsg::WhitelistForkedBlocks {
                forked_blocks: whitelist_blocks,
            },
        );
        assert!(res.is_ok());
    }

    // Check is block forked
    let is_forked: bool = from_json(
        query(
            &mut instance,
            mock_env(),
            QueryMsg::IsBlockForked {
                height: query_height,
            },
        )
        .unwrap(),
    )
    .unwrap();
    assert!(is_forked == exp_is_forked, "{}", exp_msg);
}

fn test_forked_block_range_helper(
    whitelist_blocks: Vec<(u64, u64)>,
    query_start: u64,
    query_end: u64,
    exp_forked_blocks: Vec<(u64, u64)>,
    exp_msg: &str,
) {
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

    // Add forked block as admin caller
    if !whitelist_blocks.is_empty() {
        let info: cosmwasm_std::MessageInfo = mock_info(&mock_api.addr_make(CREATOR), &[]);
        let res: ContractResult<Response> = execute(
            &mut instance,
            mock_env(),
            info,
            ExecuteMsg::WhitelistForkedBlocks {
                forked_blocks: whitelist_blocks,
            },
        );
        assert!(res.is_ok());
    }

    // Check is block forked
    let forked_blocks: Vec<(u64, u64)> = from_json(
        query(
            &mut instance,
            mock_env(),
            QueryMsg::ForkedBlocksInRange {
                start: query_start,
                end: query_end,
            },
        )
        .unwrap(),
    )
    .unwrap();
    assert!(forked_blocks == exp_forked_blocks, "{}", exp_msg);
}
