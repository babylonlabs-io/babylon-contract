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
    assert_eq!(config.btc_staking, Some(Addr::unchecked("contract1")));

    // Check that the btc-staking contract was initialized correctly
    let btc_staking_config = suite.get_btc_staking_config();
    assert_eq!(btc_staking_config.babylon, "contract0");
    assert_eq!(btc_staking_config.denom, "TOKEN");
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
