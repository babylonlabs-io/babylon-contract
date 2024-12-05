use anyhow::Result as AnyResult;
use derivative::Derivative;
use hex::ToHex;

use cosmwasm_std::{to_json_binary, Addr, Coin};

use cw_multi_test::{AppResponse, Contract, ContractWrapper, Executor};

use babylon_apis::btc_staking_api::{ActiveBtcDelegation, FinalityProvider, NewFinalityProvider};
use babylon_apis::finality_api::{IndexedBlock, PubRandCommit};
use babylon_apis::{btc_staking_api, finality_api};
use babylon_bindings::BabylonMsg;
use babylon_bindings_test::BabylonApp;
use babylon_bitcoin::chain_params::Network;

use btc_staking::msg::{ActivatedHeightResponse, FinalityProviderInfo};

use crate::msg::{EvidenceResponse, FinalityVoteResponse};
use crate::multitest::{CONTRACT1_ADDR, CONTRACT2_ADDR};

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
    )
    .with_sudo(crate::contract::sudo);
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
pub struct SuiteBuilder {
    height: Option<u64>,
    init_funds: Vec<Coin>,
}

impl SuiteBuilder {
    pub fn with_height(mut self, height: u64) -> Self {
        self.height = Some(height);
        self
    }

    pub fn with_funds(mut self, funds: &[Coin]) -> Self {
        self.init_funds = funds.to_vec();
        self
    }

    #[track_caller]
    pub fn build(self) -> Suite {
        let owner = Addr::unchecked("owner");

        let mut app = BabylonApp::new_at_height(owner.as_str(), self.height.unwrap_or(1));

        let _block_info = app.block_info();

        app.init_modules(|router, _api, storage| -> AnyResult<()> {
            router.bank.init_balance(storage, &owner, self.init_funds)
        })
        .unwrap();

        let btc_staking_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_staking());
        let btc_finality_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_finality());
        let contract_code_id = app.store_code_with_creator(owner.clone(), contract_babylon());
        let staking_params = btc_staking::test_utils::staking_params();
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
                    btc_staking_msg: Some(
                        to_json_binary(&btc_staking::msg::InstantiateMsg {
                            params: Some(staking_params),
                            admin: None,
                        })
                        .unwrap(),
                    ),
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
            .query_wasm_smart(self.staking.clone(), &btc_staking::msg::QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    pub fn get_btc_finality_config(&self) -> crate::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(self.finality.clone(), &crate::msg::QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    pub fn get_activated_height(&self) -> ActivatedHeightResponse {
        self.app
            .wrap()
            .query_wasm_smart(
                self.staking.clone(),
                &btc_staking::msg::QueryMsg::ActivatedHeight {},
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_finality_provider(&self, pk_hex: &str) -> FinalityProvider {
        self.app
            .wrap()
            .query_wasm_smart(
                self.staking.clone(),
                &btc_staking::msg::QueryMsg::FinalityProvider {
                    btc_pk_hex: pk_hex.to_string(),
                },
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_finality_provider_info(
        &self,
        pk_hex: &str,
        height: Option<u64>,
    ) -> FinalityProviderInfo {
        self.app
            .wrap()
            .query_wasm_smart(
                self.staking.clone(),
                &btc_staking::msg::QueryMsg::FinalityProviderInfo {
                    btc_pk_hex: pk_hex.to_string(),
                    height,
                },
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_finality_vote(&self, pk_hex: &str, height: u64) -> FinalityVoteResponse {
        self.app
            .wrap()
            .query_wasm_smart(
                self.finality.clone(),
                &crate::msg::QueryMsg::FinalityVote {
                    btc_pk_hex: pk_hex.to_string(),
                    height,
                },
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_indexed_block(&self, height: u64) -> IndexedBlock {
        self.app
            .wrap()
            .query_wasm_smart(
                self.finality.clone(),
                &crate::msg::QueryMsg::Block { height },
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_double_signing_evidence(&self, pk_hex: &str, height: u64) -> EvidenceResponse {
        self.app
            .wrap()
            .query_wasm_smart(
                self.finality.clone(),
                &crate::msg::QueryMsg::Evidence {
                    btc_pk_hex: pk_hex.to_string(),
                    height,
                },
            )
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
    pub fn add_delegations(&mut self, dels: &[ActiveBtcDelegation]) -> anyhow::Result<AppResponse> {
        self.app.execute_contract(
            self.babylon.clone(),
            self.staking.clone(),
            &btc_staking_api::ExecuteMsg::BtcStaking {
                new_fp: vec![],
                active_del: dels.to_vec(),
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

    #[track_caller]
    pub fn call_begin_block(
        &mut self,
        app_hash: &[u8],
        height: u64,
    ) -> anyhow::Result<AppResponse> {
        // Set the block height
        let mut block = self.app.block_info();
        block.height = height;
        self.app.set_block(block);

        // Hash is not used in the begin-block handler
        let hash_hex = format!("deadbeef{}", height);
        let app_hash_hex: String = app_hash.encode_hex();

        self.app.wasm_sudo(
            self.finality.clone(),
            &finality_api::SudoMsg::BeginBlock {
                hash_hex: hash_hex.clone(),
                app_hash_hex: app_hash_hex.clone(),
            },
        )
    }

    #[track_caller]
    pub fn call_end_block(&mut self, app_hash: &[u8], height: u64) -> anyhow::Result<AppResponse> {
        // Set the block height
        let mut block = self.app.block_info();
        block.height = height;
        self.app.set_block(block);

        // Hash is not used in the begin-block handler
        let hash_hex = format!("deadbeef{}", height);
        let app_hash_hex: String = app_hash.encode_hex();

        self.app.wasm_sudo(
            self.finality.clone(),
            &finality_api::SudoMsg::EndBlock {
                hash_hex: hash_hex.clone(),
                app_hash_hex: app_hash_hex.clone(),
            },
        )
    }

    #[track_caller]
    pub fn submit_finality_signature(
        &mut self,
        pk_hex: &str,
        height: u64,
        pub_rand: &[u8],
        proof: &tendermint_proto::crypto::Proof,
        block_hash: &[u8],
        finality_sig: &[u8],
    ) -> anyhow::Result<AppResponse> {
        // Execute the message at a higher height, so that:
        // 1. It's not rejected because of height being too low.
        // 2. The FP has consolidated power at such height
        let mut block = self.app.block_info();
        block.height = height + 1;
        self.app.set_block(block);

        self.app.execute_contract(
            Addr::unchecked("anyone"),
            self.finality.clone(),
            &finality_api::ExecuteMsg::SubmitFinalitySignature {
                fp_pubkey_hex: pk_hex.to_string(),
                height,
                pub_rand: pub_rand.into(),
                proof: proof.into(),
                block_hash: block_hash.into(),
                signature: finality_sig.into(),
            },
            &[],
        )
    }
}
