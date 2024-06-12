mod suite;

use cosmwasm_std::Addr;
use suite::SuiteBuilder;

// Some multi-test default settings
// TODO: Replace these with their address generators
const CONTRACT0_ADDR: &str = "cosmwasm1uzyszmsnca8euusre35wuqj4el3hyj8jty84kwln7du5stwwxyns2z5hxp";
const CONTRACT1_ADDR: &str = "cosmwasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s8jef58";
const TOKEN: &str = "TOKEN";

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
    assert_eq!(config.btc_staking, Some(Addr::unchecked(CONTRACT1_ADDR)));

    // Check that the btc-staking contract was initialized correctly
    let btc_staking_config = suite.get_btc_staking_config();
    assert_eq!(btc_staking_config.babylon, Addr::unchecked(CONTRACT0_ADDR));
    assert_eq!(btc_staking_config.denom, TOKEN);
}

mod instantiation {
    use super::*;

    #[test]
    fn instantiate_works() {
        let suite = SuiteBuilder::new().build();

        // Confirm the btc-staking contract has been instantiated and set
        let config = suite.get_config();
        assert_eq!(config.btc_staking, Some(Addr::unchecked(CONTRACT1_ADDR)));
    }
}

mod btc_staking {}

mod slashing {}

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
