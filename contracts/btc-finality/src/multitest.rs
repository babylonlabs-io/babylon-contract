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

    use test_utils::{get_add_finality_sig, get_pub_rand_value};

    use cosmwasm_std::Event;

    use crate::contract::tests::{
        create_new_finality_provider, get_derived_btc_delegation, get_public_randomness_commitment,
    };
    use crate::msg::FinalitySignatureResponse;

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

    #[test]
    fn commit_public_randomness_works() {
        let mut suite = SuiteBuilder::new().build();

        // Read public randomness commitment test data
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();

        // Register one FP
        // NOTE: the test data ensures that pub rand commit / finality sig are
        // signed by the 1st FP
        let new_fp = create_new_finality_provider(1);
        assert_eq!(new_fp.btc_pk_hex, pk_hex);

        suite.register_finality_providers(&[new_fp]).unwrap();

        // Now commit the public randomness for it
        suite
            .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
            .unwrap();
    }

    #[test]
    fn finality_signature_happy_path() {
        // Read public randomness commitment test data
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
        let pub_rand_one = get_pub_rand_value();
        // Read equivalent / consistent add finality signature test data
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pub_rand.start_height;

        let mut suite = SuiteBuilder::new().with_height(initial_height).build();

        // Register one FP
        // NOTE: the test data ensures that pub rand commit / finality sig are
        // signed by the 1st FP
        let new_fp = create_new_finality_provider(1);

        suite.register_finality_providers(&[new_fp]).unwrap();

        // Activated height is not set
        let res = suite.get_activated_height();
        assert_eq!(res.height, 0);

        // Add a delegation, so that the finality provider has some power
        let mut del1 = get_derived_btc_delegation(1, &[1]);
        del1.fp_btc_pk_list = vec![pk_hex.clone()];

        suite.add_delegations(&[del1]).unwrap();

        // Activated height is now set
        let res = suite.get_activated_height();
        assert_eq!(res.height, initial_height + 1);

        suite
            .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
            .unwrap();

        // Call the begin-block sudo handler(s), for completeness
        let res = suite
            .call_begin_block(&add_finality_signature.block_app_hash, initial_height + 1)
            .unwrap();
        assert_eq!(1, res.events.len());
        assert_eq!(
            res.events[0],
            Event::new("sudo").add_attribute("_contract_address", CONTRACT2_ADDR)
        );

        // Call the end-block sudo handler(s), so that the block is indexed in the store
        let res = suite
            .call_end_block(&add_finality_signature.block_app_hash, initial_height + 1)
            .unwrap();
        assert_eq!(2, res.events.len());
        assert_eq!(
            res.events[0],
            Event::new("sudo").add_attribute("_contract_address", CONTRACT2_ADDR)
        );
        assert_eq!(
            res.events[1],
            Event::new("wasm-index_block")
                .add_attribute("_contract_address", CONTRACT2_ADDR)
                .add_attribute("module", "finality")
                .add_attribute("last_height", (initial_height + 1).to_string())
        );

        // Submit a finality signature from that finality provider at height initial_height + 1
        let finality_sig = add_finality_signature.finality_sig.to_vec();
        suite
            .submit_finality_signature(
                &pk_hex,
                initial_height + 1,
                &pub_rand_one,
                &proof,
                &add_finality_signature.block_app_hash,
                &finality_sig,
            )
            .unwrap();

        // Query finality signature for that exact height
        let sig = suite.get_finality_signature(&pk_hex, initial_height + 1);
        assert_eq!(
            sig,
            FinalitySignatureResponse {
                signature: finality_sig
            }
        );
    }
}
