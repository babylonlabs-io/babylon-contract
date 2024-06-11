use cosmwasm_schema::write_api;
use cosmwasm_std::Empty;
use op_finality_gadget::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        query: QueryMsg,
        migrate: Empty,
        execute: ExecuteMsg,
    }
}
