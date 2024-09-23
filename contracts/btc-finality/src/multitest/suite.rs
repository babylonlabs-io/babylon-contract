use anyhow::Result as AnyResult;
use derivative::Derivative;

use cosmwasm_std::Addr;

use crate::multitest::{CONTRACT1_ADDR, CONTRACT2_ADDR};
use babylon_apis::btc_staking_api::NewFinalityProvider;
use babylon_apis::finality_api::PubRandCommit;
use babylon_apis::{btc_staking_api, finality_api};
use babylon_bindings::BabylonMsg;
use babylon_bindings_test::BabylonApp;
use babylon_bitcoin::chain_params::Network;
use cw_multi_test::{AppResponse, Contract, ContractWrapper, Executor};

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
        crate::contract::execute,
        crate::contract::instantiate,
        crate::contract::query,
    );
    Box::new(contract)
}

fn contract_babylon() -> Box<dyn Contract<BabylonMsg>> {
    let contract = ContractWrapper::new(
        babylon_contract::execute,
        babylon_contract::instantiate,
        babylon_contract::query,
    )
    .with_reply(babylon_contract::reply)
    .with_migrate(babylon_contract::migrate);
    Box::new(contract)
}

#[derive(Derivative)]
#[derivative(Default = "new")]
pub struct SuiteBuilder {}

impl SuiteBuilder {
    #[track_caller]
    pub fn build(self) -> Suite {
        let owner = Addr::unchecked("owner");

        let mut app = BabylonApp::new(owner.as_str());

        let _block_info = app.block_info();

        app.init_modules(|_router, _api, _storage| -> AnyResult<()> { Ok(()) })
            .unwrap();

        let btc_staking_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_staking());
        let btc_finality_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_finality());
        let contract_code_id = app.store_code_with_creator(owner.clone(), contract_babylon());
        let contract = app
            .instantiate_contract(
                contract_code_id,
                owner.clone(),
                &babylon_contract::msg::contract::InstantiateMsg {
                    network: Network::Testnet,
                    babylon_tag: "01020304".to_string(),
                    btc_confirmation_depth: 1,
                    checkpoint_finalization_timeout: 10,
                    notify_cosmos_zone: false,
                    btc_staking_code_id: Some(btc_staking_code_id),
                    btc_staking_msg: None,
                    btc_finality_code_id: Some(btc_finality_code_id),
                    btc_finality_msg: None,
                    admin: Some(owner.to_string()),
                    consumer_name: Some("TestConsumer".to_string()),
                    consumer_description: Some("Test Consumer Description".to_string()),
                },
                &[],
                "babylon",
                Some(owner.to_string()),
            )
            .unwrap();

        Suite {
            app,
            code_id: contract_code_id,
            babylon: contract,
            staking: Addr::unchecked(CONTRACT1_ADDR),
            finality: Addr::unchecked(CONTRACT2_ADDR),
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
    pub babylon: Addr,
    /// Staking contract address
    pub staking: Addr,
    /// Finality contract address
    pub finality: Addr,
    /// Admin of babylon and btc-staking contracts
    pub owner: Addr,
}

impl Suite {
    #[allow(dead_code)]
    pub fn admin(&self) -> &str {
        self.owner.as_str()
    }

    #[track_caller]
    pub fn get_babylon_config(&self) -> babylon_contract::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(
                self.babylon.clone(),
                &babylon_contract::msg::contract::QueryMsg::Config {},
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_btc_staking_config(&self) -> btc_staking::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(CONTRACT1_ADDR, &btc_staking::msg::QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    pub fn get_btc_finality_config(&self) -> crate::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(CONTRACT2_ADDR, &crate::msg::QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    pub fn register_finality_providers(
        &mut self,
        fps: &[NewFinalityProvider],
    ) -> anyhow::Result<AppResponse> {
        self.app.execute_contract(
            self.babylon.clone(),
            self.staking.clone(),
            &btc_staking_api::ExecuteMsg::BtcStaking {
                new_fp: fps.to_vec(),
                active_del: vec![],
                slashed_del: vec![],
                unbonded_del: vec![],
            },
            &[],
        )
    }

    #[track_caller]
    pub fn commit_public_randomness(
        &mut self,
        pk_hex: &str,
        pub_rand: &PubRandCommit,
        pubrand_signature: &[u8],
    ) -> anyhow::Result<AppResponse> {
        self.app.execute_contract(
            Addr::unchecked("anyone"),
            self.finality.clone(),
            &finality_api::ExecuteMsg::CommitPublicRandomness {
                fp_pubkey_hex: pk_hex.to_string(),
                start_height: pub_rand.start_height,
                num_pub_rand: pub_rand.num_pub_rand,
                commitment: pub_rand.commitment.clone().into(),
                signature: pubrand_signature.into(),
            },
            &[],
        )
    }
}
