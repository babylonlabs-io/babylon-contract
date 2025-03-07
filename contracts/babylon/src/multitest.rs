mod suite;

use cosmwasm_std::Addr;
use suite::SuiteBuilder;

// Some multi-test default settings
// TODO: Replace these with their address generators
// Babylon contract
const CONTRACT0_ADDR: &str = "cosmwasm1nnzavhgqucflnjpkmstm9ld9d54ywcgep0ej2em8lxaqcm0tuugspxy2zj";
// BTC Light Client contract
const CONTRACT1_ADDR: &str = "cosmwasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s8jef58";
// BTC Staking contract
const CONTRACT2_ADDR: &str = "cosmwasm1nc5tatafv6eyq7llkr2gv50ff9e22mnf70qgjlv737ktmt4eswrqt8utkp";
// BTC Finality contract
const CONTRACT3_ADDR: &str = "cosmwasm17p9rzwnnfxcjp32un9ug7yhhzgtkhvl9jfksztgw5uh69wac2pgsnuzwl9";

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
    assert_eq!(
        config.btc_light_client,
        Some(Addr::unchecked(CONTRACT1_ADDR))
    );
    assert_eq!(config.btc_staking, Some(Addr::unchecked(CONTRACT2_ADDR)));
    assert_eq!(config.btc_finality, Some(Addr::unchecked(CONTRACT3_ADDR)));

    // Check that the btc-staking contract was initialized correctly
    let btc_staking_config = suite.get_btc_staking_config();
    assert_eq!(btc_staking_config.babylon, Addr::unchecked(CONTRACT0_ADDR));

    // Check that the btc-finality contract was initialized correctly
    let btc_finality_config = suite.get_btc_finality_config();
    assert_eq!(btc_finality_config.babylon, Addr::unchecked(CONTRACT0_ADDR));
}

mod instantiation {
    use super::*;
    use cosmwasm_std::to_json_string;

    #[test]
    fn instantiate_works() {
        let suite = SuiteBuilder::new().build();

        // Confirm the btc-light-client contract has been instantiated and set
        let config = suite.get_config();
        assert_eq!(
            config.btc_light_client,
            Some(Addr::unchecked(CONTRACT1_ADDR))
        );
        // Confirm the btc-staking contract has been instantiated and set
        assert_eq!(config.btc_staking, Some(Addr::unchecked(CONTRACT2_ADDR)));
        // Confirm the btc-finality contract has been instantiated and set
        assert_eq!(config.btc_finality, Some(Addr::unchecked(CONTRACT3_ADDR)));
    }

    #[test]
    fn instantiate_light_client_msg_works() {
        let params = btc_light_client::msg::InstantiateMsg {
            network: babylon_bitcoin::chain_params::Network::Testnet,
            btc_confirmation_depth: 6,
            checkpoint_finalization_timeout: 100,
        };
        let suite = SuiteBuilder::new()
            .with_light_client_msg(&to_json_string(&params).unwrap())
            .build();

        // Confirm the btc-light-client contract has been instantiated and set
        let config = suite.get_config();
        assert_eq!(
            config.btc_light_client,
            Some(Addr::unchecked(CONTRACT1_ADDR))
        );
        // Confirm the btc-staking contract has been instantiated and set
        assert_eq!(config.btc_staking, Some(Addr::unchecked(CONTRACT2_ADDR)));
        // Confirm the btc-finality contract has been instantiated and set
        assert_eq!(config.btc_finality, Some(Addr::unchecked(CONTRACT3_ADDR)));

        // Check that the btc-light-client contract was initialized correctly
        let btc_light_client_config = suite.get_btc_light_client_config();
        assert_eq!(btc_light_client_config.network, params.network);
        assert_eq!(
            btc_light_client_config.btc_confirmation_depth,
            params.btc_confirmation_depth
        );
        assert_eq!(
            btc_light_client_config.checkpoint_finalization_timeout,
            params.checkpoint_finalization_timeout
        );
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

        // Confirm the btc-light-client contract has been instantiated and set
        let config = suite.get_config();
        assert_eq!(
            config.btc_light_client,
            Some(Addr::unchecked(CONTRACT1_ADDR))
        );
        // Confirm the btc-staking contract has been instantiated and set
        assert_eq!(config.btc_staking, Some(Addr::unchecked(CONTRACT2_ADDR)));
        // Confirm the btc-finality contract has been instantiated and set
        assert_eq!(config.btc_finality, Some(Addr::unchecked(CONTRACT3_ADDR)));
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

        // Confirm the btc-light-client contract has been instantiated and set
        let config = suite.get_config();
        assert_eq!(
            config.btc_light_client,
            Some(Addr::unchecked(CONTRACT1_ADDR))
        );
        // Confirm the btc-staking contract has been instantiated and set
        assert_eq!(config.btc_staking, Some(Addr::unchecked(CONTRACT2_ADDR)));
        // Confirm the btc-finality contract has been instantiated and set
        assert_eq!(config.btc_finality, Some(Addr::unchecked(CONTRACT3_ADDR)));
    }

    #[test]
    fn instantiate_ibc_ics20_works() {
        let suite = SuiteBuilder::new().with_ics20_channel("channel-10").build();

        // Confirm the transfer info has been set
        let channel_id = suite.get_transfer_info().unwrap();
        assert_eq!(channel_id, "channel-10");
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
