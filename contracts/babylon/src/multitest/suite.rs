use crate::msg::ibc::TransferInfoResponse;
use anyhow::Result as AnyResult;
use derivative::Derivative;

use babylon_bindings::BabylonMsg;
use babylon_bindings_test::BabylonApp;
use babylon_bitcoin::chain_params::Network;
use cosmwasm_std::{Addr, Binary, Empty};
use cw_multi_test::{AppResponse, Contract, ContractWrapper, Executor};

use crate::msg::contract::{InstantiateMsg, QueryMsg};
use crate::multitest::{CONTRACT1_ADDR, CONTRACT2_ADDR, CONTRACT3_ADDR};
use crate::state::config::Config;

fn contract_btc_light_client() -> Box<dyn Contract<BabylonMsg>> {
    let contract = ContractWrapper::new(
        btc_light_client::contract::execute,
        btc_light_client::contract::instantiate,
        btc_light_client::contract::query,
    );
    Box::new(contract)
}

fn contract_btc_staking() -> Box<dyn Contract<BabylonMsg>> {
    let contract = ContractWrapper::new(
        btc_staking::contract::execute,
        btc_staking::contract::instantiate,
        btc_staking::contract::query,
    );
    Box::new(contract)
}

fn contract_btc_finality() -> Box<dyn Contract<BabylonMsg>> {
    let contract = ContractWrapper::new(
        btc_finality::contract::execute,
        btc_finality::contract::instantiate,
        btc_finality::contract::query,
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
    light_client_msg: Option<String>,
    staking_msg: Option<String>,
    finality_msg: Option<String>,
    ics20_channel_id: Option<String>,
}

impl SuiteBuilder {
    /// Sets initial number of tokens on address
    #[allow(dead_code)]
    pub fn with_funds(mut self, addr: &str, amount: u128) -> Self {
        self.funds.push((Addr::unchecked(addr), amount));
        self
    }

    /// Sets the light client contract instantiation message
    pub fn with_light_client_msg(mut self, msg: &str) -> Self {
        self.light_client_msg = Some(msg.into());
        self
    }

    /// Sets the staking contract instantiation message
    pub fn with_staking_msg(mut self, msg: &str) -> Self {
        self.staking_msg = Some(msg.into());
        self
    }

    /// Sets the finality contract instantiation message
    pub fn with_finality_msg(mut self, msg: &str) -> Self {
        self.finality_msg = Some(msg.into());
        self
    }

    /// Sets the IBC transfer info
    pub fn with_ics20_channel(mut self, channel_id: &str) -> Self {
        self.ics20_channel_id = Some(channel_id.to_owned());
        self
    }

    #[track_caller]
    pub fn build(self) -> Suite {
        let _funds = self.funds;

        let owner = Addr::unchecked("owner");

        let mut app = BabylonApp::new(owner.as_str());

        let _block_info = app.block_info();

        app.init_modules(|_router, _api, _storage| -> AnyResult<()> { Ok(()) })
            .unwrap();

        let btc_light_client_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_light_client());
        let btc_staking_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_staking());
        let btc_finality_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_finality());
        let contract_code_id = app.store_code_with_creator(owner.clone(), contract_babylon());

        let light_client_msg = self
            .light_client_msg
            .map(|msg| Binary::from(msg.as_bytes()));
        let staking_msg = self.staking_msg.map(|msg| Binary::from(msg.as_bytes()));
        let finality_msg = self.finality_msg.map(|msg| Binary::from(msg.as_bytes()));
        let contract = app
            .instantiate_contract(
                contract_code_id,
                owner.clone(),
                &InstantiateMsg {
                    network: Network::Testnet,
                    babylon_tag: "01020304".to_string(),
                    btc_confirmation_depth: 1,
                    checkpoint_finalization_timeout: 10,
                    notify_cosmos_zone: false,
                    btc_light_client_code_id: Some(btc_light_client_code_id),
                    btc_light_client_msg: light_client_msg,
                    btc_staking_code_id: Some(btc_staking_code_id),
                    btc_staking_msg: staking_msg,
                    btc_finality_code_id: Some(btc_finality_code_id),
                    btc_finality_msg: finality_msg,
                    admin: Some(owner.to_string()),
                    consumer_name: Some("TestConsumer".to_string()),
                    consumer_description: Some("Test Consumer Description".to_string()),
                    ics20_channel_id: self.ics20_channel_id,
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
}

impl Suite {
    pub fn admin(&self) -> &str {
        self.owner.as_str()
    }

    #[track_caller]
    pub fn get_config(&self) -> Config {
        self.app
            .wrap()
            .query_wasm_smart(self.contract.clone(), &QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    pub fn get_btc_light_client_config(&self) -> btc_light_client::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(CONTRACT1_ADDR, &btc_light_client::msg::QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    pub fn get_btc_staking_config(&self) -> btc_staking::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(CONTRACT2_ADDR, &btc_staking::msg::QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    pub fn get_btc_finality_config(&self) -> btc_finality::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(CONTRACT3_ADDR, &btc_finality::msg::QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    pub fn get_transfer_info(&self) -> TransferInfoResponse {
        self.app
            .wrap()
            .query_wasm_smart(self.contract.clone(), &QueryMsg::TransferInfo {})
            .unwrap()
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
