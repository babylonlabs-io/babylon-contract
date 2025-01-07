mod suite;

use cosmwasm_std::Addr;
use suite::SuiteBuilder;

#[test]
fn initialization() {
    let suite = SuiteBuilder::new().build();

    // Check that the contracts were initialized correctly
    let config = suite.get_config();
    assert_eq!(
        config.network,
        babylon_bitcoin::chain_params::Network::Testnet
    );
    assert_eq!(config.babylon_tag, [1, 2, 3, 4]);
    assert_eq!(config.btc_confirmation_depth, 1);
    assert_eq!(config.checkpoint_finalization_timeout, 10);
    assert!(!config.notify_cosmos_zone);
    assert!(!suite.btc_staking_contract.to_string().is_empty());
    assert!(!suite.btc_finality_contract.to_string().is_empty());
}

mod instantiation {
    use super::*;
    use crate::msg::ibc::Recipient;
    use babylon_apis::{to_bech32_addr, to_module_canonical_addr};
    use cosmwasm_std::to_json_string;

    #[test]
    fn instantiate_works() {
        let suite = SuiteBuilder::new().build();

        // Confirm the btc-staking contract has been instantiated and set
        assert!(!suite.btc_staking_contract.to_string().is_empty());
        // Confirm the btc-finality contract has been instantiated and set
        assert!(!suite.btc_finality_contract.to_string().is_empty());
    }

    #[test]
    fn instantiate_staking_msg_works() {
        // Params setting is an all-or-nothing operation, i.e. all the params have to be set
        let params = btc_staking::state::config::Params {
            covenant_pks: vec![],
            covenant_quorum: 1,
            btc_network: babylon_bitcoin::chain_params::Network::Regtest,
            slashing_pk_script: String::from("76a914010101010101010101010101010101010101010188ab"),
            min_slashing_tx_fee_sat: 10000,
            slashing_rate: String::from("0.1"),
        };
        let staking_instantiation_msg = btc_staking::msg::InstantiateMsg {
            params: Some(params),
            admin: None,
        };
        let suite = SuiteBuilder::new()
            .with_staking_msg(&to_json_string(&staking_instantiation_msg).unwrap())
            .build();

        // Confirm the btc-staking contract has been instantiated and set
        let config = suite.get_config();
        assert_eq!(config.btc_staking, Some(Addr::unchecked(CONTRACT1_ADDR)));
        // Confirm the btc-finality contract has been instantiated and set
        assert_eq!(config.btc_finality, Some(Addr::unchecked(CONTRACT2_ADDR)));
    }

    #[test]
    fn instantiate_finality_msg_works() {
        // Params setting is an all-or-nothing operation, i.e. all the params have to be set
        let params = btc_finality::state::config::Params {
            epoch_length: 10,
            max_active_finality_providers: 5,
            min_pub_rand: 2,
            finality_inflation_rate: "0.035".parse().unwrap(),
        };
        let finality_instantiation_msg = btc_finality::msg::InstantiateMsg {
            params: Some(params),
            admin: None,
        };
        let suite = SuiteBuilder::new()
            .with_finality_msg(&to_json_string(&finality_instantiation_msg).unwrap())
            .build();

        // Confirm the btc-staking contract has been instantiated and set
        let config = suite.get_config();
        assert_eq!(config.btc_staking, Some(Addr::unchecked(CONTRACT1_ADDR)));
        // Confirm the btc-finality contract has been instantiated and set
        assert_eq!(config.btc_finality, Some(Addr::unchecked(CONTRACT2_ADDR)));
    }

    #[test]
    fn instantiate_ibc_transfer_module_addr_works() {
        let suite = SuiteBuilder::new()
            .with_ibc_transfer_info(
                "channel-10",
                Recipient::ModuleAddr("module-addr".to_string()),
            )
            .build();

        // Confirm the transfer info has been set
        let transfer_info = suite.get_transfer_info().unwrap();
        assert_eq!(transfer_info.channel_id, "channel-10");
        assert_eq!(
            transfer_info.to_address,
            to_bech32_addr("bbn", &to_module_canonical_addr("module-addr"))
                .unwrap()
                .to_string()
        );
        assert_eq!(transfer_info.address_type, "module");
    }

    #[test]
    fn instantiate_ibc_transfer_contract_addr_works() {
        let suite = SuiteBuilder::new()
            .with_ibc_transfer_info(
                "channel-10",
                Recipient::ContractAddr("bbn1wdptld6nw2plxzf0w62gqc60tlw5kypzej89y3".to_string()),
            )
            .build();

        // Confirm the transfer info has been set
        let transfer_info = suite.get_transfer_info().unwrap();
        assert_eq!(transfer_info.channel_id, "channel-10");
        assert_eq!(
            transfer_info.to_address,
            "bbn1wdptld6nw2plxzf0w62gqc60tlw5kypzej89y3".to_string()
        );
        assert_eq!(transfer_info.address_type, "contract");
    }
}

mod migration {
    use super::*;
    use cosmwasm_std::Empty;

    #[test]
    fn migrate_works() {
        let mut suite = SuiteBuilder::new().build();
        let admin = suite.admin().to_string();

        suite.migrate(&admin, Empty {}).unwrap();
    }
}
