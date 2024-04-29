mod suite;

use suite::SuiteBuilder;

#[test]
fn initialization() {
    let _suite = SuiteBuilder::new().build();
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
