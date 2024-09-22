mod suite;

use cosmwasm_std::Addr;
use suite::SuiteBuilder;

// Some multi-test default settings
// TODO: Replace these with their address generators
const CONTRACT0_ADDR: &str = "cosmwasm19mfs8tl4s396u7vqw9rrnsmrrtca5r66p7v8jvwdxvjn3shcmllqupdgxu";
const CONTRACT1_ADDR: &str = "cosmwasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s8jef58";
const CONTRACT2_ADDR: &str = "cosmwasm1nc5tatafv6eyq7llkr2gv50ff9e22mnf70qgjlv737ktmt4eswrqt8utkp";

mod instantiation {
    use super::*;

    #[test]
    fn instantiate_works() {
        let suite = SuiteBuilder::new().build();

        // Confirm the btc-staking contract has been instantiated and set
        let config = suite.get_babylon_config();
        assert_eq!(config.btc_staking, Some(Addr::unchecked(CONTRACT1_ADDR)));
        // Confirm the btc-finality contract has been instantiated and set
        assert_eq!(config.btc_finality, Some(Addr::unchecked(CONTRACT2_ADDR)));
        // Check that the btc-staking contract was initialized correctly
        let btc_staking_config = suite.get_btc_staking_config();
        assert_eq!(btc_staking_config.babylon, Addr::unchecked(CONTRACT0_ADDR));

        // Check that the btc-finality contract was initialized correctly
        let btc_finality_config = suite.get_btc_finality_config();
        assert_eq!(btc_finality_config.babylon, Addr::unchecked(CONTRACT0_ADDR));
    }
}
