mod suite;

use cosmwasm_std::Addr;
use suite::SuiteBuilder;

// Some multi-test default settings
// TODO: Replace these with their address generators
// Babylon contract
const CONTRACT0_ADDR: &str = "cosmwasm19mfs8tl4s396u7vqw9rrnsmrrtca5r66p7v8jvwdxvjn3shcmllqupdgxu";
// BTC Staking contract
const CONTRACT1_ADDR: &str = "cosmwasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s8jef58";
// BTC Finality contract
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

mod finality {
    use super::*;

    use crate::contract::tests::{
        create_new_finality_provider, get_derived_btc_delegation, get_public_randomness_commitment,
    };
    use crate::msg::FinalitySignatureResponse;
    use babylon_apis::finality_api::IndexedBlock;

    use cosmwasm_std::Event;
    use test_utils::{get_add_finality_sig, get_pub_rand_value};

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

    #[test]
    fn finality_round_works() {
        // Read public randomness commitment test data
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
        let pub_rand_one = get_pub_rand_value();
        // Read equivalent / consistent add finality signature test data
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pub_rand.start_height;

        let mut suite = SuiteBuilder::new().with_height(initial_height).build();

        // signed by the 1st FP
        let new_fp = create_new_finality_provider(1);
        assert_eq!(new_fp.btc_pk_hex, pk_hex);

        suite
            .register_finality_providers(&[new_fp.clone()])
            .unwrap();

        // Add a delegation, so that the finality provider has some power
        let mut del1 = get_derived_btc_delegation(1, &[1]);
        del1.fp_btc_pk_list = vec![pk_hex.clone()];

        suite.add_delegations(&[del1.clone()]).unwrap();

        // Check that the finality provider power has been updated
        let fp_info = suite.get_finality_provider_info(&new_fp.btc_pk_hex, None);
        assert_eq!(fp_info.power, del1.total_sat);

        // Submit public randomness commitment for the FP and the involved heights
        suite
            .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
            .unwrap();

        // Call the begin-block sudo handler, for completeness
        suite
            .call_begin_block(&add_finality_signature.block_app_hash, initial_height + 1)
            .unwrap();

        // Call the end-block sudo handler, so that the block is indexed in the store
        suite
            .call_end_block(&add_finality_signature.block_app_hash, initial_height + 1)
            .unwrap();

        // Submit a finality signature from that finality provider at height initial_height + 1
        let submit_height = initial_height + 1;
        let finality_sig = add_finality_signature.finality_sig.to_vec();
        suite
            .submit_finality_signature(
                &pk_hex,
                submit_height,
                &pub_rand_one,
                &proof,
                &add_finality_signature.block_app_hash,
                &finality_sig,
            )
            .unwrap();

        // Call the begin blocker, to compute the active FP set
        suite
            .call_begin_block(&add_finality_signature.block_app_hash, submit_height)
            .unwrap();

        // Call the end blocker, to process the finality signatures
        let res = suite
            .call_end_block(&add_finality_signature.block_app_hash, submit_height)
            .unwrap();
        assert_eq!(3, res.events.len());
        assert_eq!(
            res.events[0],
            Event::new("sudo").add_attribute("_contract_address", CONTRACT2_ADDR)
        );
        assert_eq!(
            res.events[1],
            Event::new("wasm-index_block")
                .add_attribute("_contract_address", CONTRACT2_ADDR)
                .add_attribute("module", "finality")
                .add_attribute("last_height", submit_height.to_string())
        );
        assert_eq!(
            res.events[2],
            Event::new("wasm-finalize_block")
                .add_attribute("_contract_address", CONTRACT2_ADDR)
                .add_attribute("module", "finality")
                .add_attribute("finalized_height", submit_height.to_string())
        );

        // Assert the submitted block has been indexed and finalised
        let indexed_block = suite.get_indexed_block(submit_height);
        assert_eq!(
            indexed_block,
            IndexedBlock {
                height: submit_height,
                app_hash: add_finality_signature.block_app_hash.to_vec(),
                finalized: true,
            }
        );
    }
}

mod slashing {
    use babylon_apis::finality_api::IndexedBlock;
    use test_utils::{get_add_finality_sig, get_add_finality_sig_2, get_pub_rand_value};

    use crate::contract::tests::{
        create_new_finality_provider, get_derived_btc_delegation, get_public_randomness_commitment,
    };
    use crate::multitest::suite::SuiteBuilder;

    #[test]
    fn slashing_works() {
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

        suite
            .register_finality_providers(&[new_fp.clone()])
            .unwrap();

        // Add a delegation, so that the finality provider has some power
        let mut del1 = get_derived_btc_delegation(1, &[1]);
        del1.fp_btc_pk_list = vec![pk_hex.clone()];

        suite.add_delegations(&[del1.clone()]).unwrap();

        // Check that the finality provider power has been updated
        let fp_info = suite.get_finality_provider_info(&new_fp.btc_pk_hex, None);
        assert_eq!(fp_info.power, del1.total_sat);

        // Submit public randomness commitment for the FP and the involved heights
        suite
            .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
            .unwrap();

        // Call the begin-block sudo handler at the next height, for completeness
        let next_height = initial_height + 1;
        suite.app.advance_blocks(next_height - initial_height);
        suite
            .call_begin_block(&add_finality_signature.block_app_hash, next_height)
            .unwrap();

        // Call the end-block sudo handler, so that the block is indexed in the store
        suite
            .call_end_block(&add_finality_signature.block_app_hash, next_height)
            .unwrap();

        // Submit a finality signature from that finality provider at next height (initial_height + 1)
        let submit_height = next_height;
        // Increase block height
        let next_height = next_height + 1;
        suite.app.advance_blocks(next_height - submit_height);
        // Call the begin-block sudo handler at the next height, for completeness
        suite
            .call_begin_block(&add_finality_signature.block_app_hash, next_height)
            .unwrap();

        let finality_signature = add_finality_signature.finality_sig.to_vec();
        suite
            .submit_finality_signature(
                &pk_hex,
                submit_height,
                &pub_rand_one,
                &proof,
                &add_finality_signature.block_app_hash,
                &finality_signature,
            )
            .unwrap();

        // Submitting the same signature twice is tolerated
        suite
            .submit_finality_signature(
                &pk_hex,
                submit_height,
                &pub_rand_one,
                &proof,
                &add_finality_signature.block_app_hash,
                &finality_signature,
            )
            .unwrap();

        // Submit another (different and valid) finality signature, from the same finality provider
        // at the same height, and with the same proof
        let add_finality_signature_2 = get_add_finality_sig_2();
        let res = suite
            .submit_finality_signature(
                &pk_hex,
                submit_height,
                &pub_rand_one,
                &proof,
                &add_finality_signature_2.block_app_hash,
                &add_finality_signature_2.finality_sig,
            )
            .unwrap();

        // Assert the double signing evidence is proper
        let btc_pk = hex::decode(pk_hex.clone()).unwrap();
        let evidence = suite
            .get_double_signing_evidence(&pk_hex, submit_height)
            .evidence
            .unwrap();
        assert_eq!(evidence.block_height, submit_height);
        assert_eq!(evidence.fp_btc_pk, btc_pk);

        // Assert the slashing event is there
        assert_eq!(4, res.events.len());
        // Assert the slashing event is proper (slashing is the 2nd event in the list)
        assert_eq!(
            res.events[1].ty,
            "wasm-slashed_finality_provider".to_string()
        );

        // Call the end-block sudo handler for completeness / realism
        suite
            .call_end_block(&add_finality_signature_2.block_app_hash, next_height)
            .unwrap();

        // Call the next (final) block begin blocker, to compute the active FP set
        let final_height = next_height + 1;
        suite.app.advance_blocks(final_height - next_height);
        suite
            .call_begin_block("deadbeef02".as_bytes(), final_height)
            .unwrap();

        // Call the next (final) block end blocker, to process the finality signatures
        suite
            .call_end_block("deadbeef02".as_bytes(), final_height)
            .unwrap();

        // Assert the canonical block has been indexed (and finalised)
        let indexed_block = suite.get_indexed_block(submit_height);
        assert_eq!(
            indexed_block,
            IndexedBlock {
                height: submit_height,
                app_hash: add_finality_signature.block_app_hash.to_vec(),
                finalized: true,
            }
        );

        // Assert the finality provider has been slashed
        let fp = suite.get_finality_provider(&pk_hex);
        assert_eq!(fp.slashed_height, next_height);
    }
}
