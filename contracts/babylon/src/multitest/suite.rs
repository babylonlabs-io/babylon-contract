use crate::msg::contract::{InstantiateMsg, QueryMsg};
use crate::msg::ibc::TransferInfoResponse;
use crate::msg::ibc::{IbcTransferInfo, Recipient};
use crate::state::config::Config;
use anyhow::Result as AnyResult;
use babylon_bindings::query::BabylonQuery;
use derivative::Derivative;

use cosmwasm_std::{Addr, Binary, Empty};
use cw_multi_test::{AppResponse, Contract, ContractWrapper, Executor};

use babylon_bindings::BabylonMsg;
use babylon_bindings_test::BabylonApp;
use babylon_bitcoin::chain_params::Network;

fn contract_btc_staking() -> Box<dyn Contract<BabylonMsg, BabylonQuery>> {
    let contract = ContractWrapper::new(
        btc_staking::contract::execute,
        btc_staking::contract::instantiate,
        btc_staking::contract::query,
    );
    Box::new(contract)
}

fn contract_btc_finality() -> Box<dyn Contract<BabylonMsg, BabylonQuery>> {
    let contract = ContractWrapper::new(
        btc_finality::contract::execute,
        btc_finality::contract::instantiate,
        btc_finality::contract::query,
    );
    Box::new(contract)
}

fn contract_babylon() -> Box<dyn Contract<BabylonMsg, BabylonQuery>> {
    let contract = ContractWrapper::new(crate::execute, crate::instantiate, crate::query)
        .with_migrate(crate::migrate);
    Box::new(contract)
}

#[derive(Derivative)]
#[derivative(Default = "new")]
pub struct SuiteBuilder {
    funds: Vec<(Addr, u128)>,
    staking_msg: Option<String>,
    finality_msg: Option<String>,
    transfer_info: Option<IbcTransferInfo>,
}

impl SuiteBuilder {
    /// Sets initial number of tokens on address
    #[allow(dead_code)]
    pub fn with_funds(mut self, addr: &str, amount: u128) -> Self {
        self.funds.push((Addr::unchecked(addr), amount));
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
    #[allow(dead_code)]
    pub fn with_ibc_transfer_info(mut self, channel_id: &str, recipient: Recipient) -> Self {
        let transfer_info = IbcTransferInfo {
            channel_id: channel_id.into(),
            recipient,
        };
        self.transfer_info = Some(transfer_info);
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

        // Store and instantiate the Babylon contract
        let contract_code_id = app.store_code_with_creator(owner.clone(), contract_babylon());

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
                    admin: Some(owner.to_string()),
                    consumer_name: Some("TestConsumer".to_string()),
                    consumer_description: Some("Test Consumer Description".to_string()),
                    transfer_info: self.transfer_info,
                },
                &[],
                "babylon",
                Some(owner.to_string()),
            )
            .unwrap();

        let btc_staking_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_staking());
        let btc_staking_contract = app
            .instantiate_contract(
                btc_staking_code_id,
                owner.clone(),
                &btc_staking::msg::InstantiateMsg {
                    admin: None,
                    params: None,
                },
                &[],
                "btc-staking",
                Some(owner.to_string()),
            )
            .unwrap();

        let btc_finality_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_finality());
        let btc_finality_contract = app
            .instantiate_contract(
                btc_finality_code_id,
                owner.clone(),
                &btc_finality::msg::InstantiateMsg {
                    admin: None,
                    params: None,
                },
                &[],
                "btc-finality",
                Some(owner.to_string()),
            )
            .unwrap();

        Suite {
            app,
            code_id: contract_code_id,
            babylon_contract: contract,
            btc_staking_contract: btc_staking_contract,
            btc_finality_contract: btc_finality_contract,
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
    pub babylon_contract: Addr,
    /// BTC staking contract address
    pub btc_staking_contract: Addr,
    /// BTC finality contract address
    pub btc_finality_contract: Addr,
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
            .query_wasm_smart(self.babylon_contract.clone(), &QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    pub fn get_btc_staking_config(&self) -> btc_staking::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(
                self.btc_staking_contract.clone(),
                &btc_staking::msg::QueryMsg::Config {},
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_btc_finality_config(&self) -> btc_finality::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(
                self.btc_finality_contract.clone(),
                &btc_finality::msg::QueryMsg::Config {},
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_transfer_info(&self) -> TransferInfoResponse {
        self.app
            .wrap()
            .query_wasm_smart(self.babylon_contract.clone(), &QueryMsg::TransferInfo {})
            .unwrap()
    }

    pub fn migrate(&mut self, addr: &str, msg: Empty) -> AnyResult<AppResponse> {
        self.app.migrate_contract(
            Addr::unchecked(addr),
            self.babylon_contract.clone(),
            &msg,
            self.code_id,
        )
    }
}
