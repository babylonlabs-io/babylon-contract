use crate::msg::contract::InstantiateMsg;
use anyhow::Result as AnyResult;
use babylon_bindings::BabylonMsg;
use babylon_bindings_test::BabylonApp;
use babylon_bitcoin::chain_params::Network;
use cosmwasm_std::{Addr, Empty, StdResult};
use cw_multi_test::{AppResponse, Contract, ContractWrapper, Executor};
use derivative::Derivative;

fn contract_btc_staking() -> Box<dyn Contract<BabylonMsg>> {
    let contract = ContractWrapper::new(
        btc_staking::contract::execute,
        btc_staking::contract::instantiate,
        btc_staking::contract::query,
    );
    Box::new(contract)
}

fn contract_babylon() -> Box<dyn Contract<BabylonMsg>> {
    let contract = ContractWrapper::new(crate::execute, crate::instantiate, crate::query)
        .with_reply(crate::reply)
        .with_migrate(crate::migrate);
    Box::new(contract)
}

#[derive(Derivative)]
#[derivative(Default = "new")]
pub struct SuiteBuilder {
    funds: Vec<(Addr, u128)>,
    #[derivative(Default(value = "\"osmo\".to_owned()"))]
    denom: String,
}

impl SuiteBuilder {
    /// Sets initial number of tokens on address
    #[allow(dead_code)]
    pub fn with_funds(mut self, addr: &str, amount: u128) -> Self {
        self.funds.push((Addr::unchecked(addr), amount));
        self
    }

    #[track_caller]
    pub fn build(self) -> Suite {
        let _funds = self.funds;

        let owner = Addr::unchecked("owner");

        let denom = self.denom;

        let mut app = BabylonApp::new(owner.as_str());

        let _block_info = app.block_info();

        app.init_modules(|_router, _api, _storage| -> AnyResult<()> { Ok(()) })
            .unwrap();

        let btc_staking_code_id = app.store_code(contract_btc_staking());
        let contract_code_id = app.store_code(contract_babylon());
        let contract = app
            .instantiate_contract(
                contract_code_id,
                owner.clone(),
                &InstantiateMsg {
                    network: Network::Mainnet,
                    babylon_tag: "01020304".to_string(),
                    btc_confirmation_depth: 1,
                    checkpoint_finalization_timeout: 1,
                    notify_cosmos_zone: false,
                    btc_staking_code_id: Some(btc_staking_code_id),
                    admin: Some(owner.to_string()),
                },
                &[],
                "babylon",
                Some(owner.to_string()),
            )
            .unwrap();

        Suite {
            app,
            code_id: contract_code_id,
            contract,
            owner,
            denom,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Suite {
    #[derivative(Debug = "ignore")]
    pub app: BabylonApp,
    /// The code id of the babylon contract
    code_id: u64,
    /// Babylon contract address
    pub contract: Addr,
    /// Admin of babylon and btc-staking contracts
    pub owner: Addr,
    /// Denom of tokens in this Consumer
    pub denom: String,
}

impl Suite {
    pub fn admin(&self) -> &str {
        self.owner.as_str()
    }

    /// Shortcut for querying token balance of address
    #[allow(dead_code)]
    pub fn token_balance(&self, owner: &str) -> StdResult<u128> {
        let amount = self
            .app
            .wrap()
            .query_balance(Addr::unchecked(owner), &self.denom)?
            .amount;
        Ok(amount.into())
    }

    pub fn migrate(&mut self, addr: &str, msg: Empty) -> AnyResult<AppResponse> {
        self.app.migrate_contract(
            Addr::unchecked(addr),
            self.contract.clone(),
            &msg,
            self.code_id,
        )
    }
}
