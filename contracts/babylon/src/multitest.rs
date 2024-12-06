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

    #[test]
    fn instantiate_works() {
        let suite = SuiteBuilder::new().build();

        // Confirm the btc-staking contract has been instantiated and set
        assert!(!suite.btc_staking_contract.to_string().is_empty());
        // Confirm the btc-finality contract has been instantiated and set
        assert!(!suite.btc_finality_contract.to_string().is_empty());
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
