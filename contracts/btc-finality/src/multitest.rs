mod suite;

use cosmwasm_std::Addr;
use suite::SuiteBuilder;

// Some multi-test default settings
// TODO: Replace these with their address generators
// Babylon contract
const BABYLON_CONTRACT_ADDR: &str =
    "cosmwasm1nnzavhgqucflnjpkmstm9ld9d54ywcgep0ej2em8lxaqcm0tuugspxy2zj";
// BTC Light Client contract
const BTC_LIGHT_CLIENT_CONTRACT_ADDR: &str =
    "cosmwasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s8jef58";
// BTC Staking contract
const BTC_STAKING_CONTRACT_ADDR: &str =
    "cosmwasm1nc5tatafv6eyq7llkr2gv50ff9e22mnf70qgjlv737ktmt4eswrqt8utkp";
// BTC Finality contract
const BTC_FINALITY_CONTRACT_ADDR: &str =
    "cosmwasm17p9rzwnnfxcjp32un9ug7yhhzgtkhvl9jfksztgw5uh69wac2pgsnuzwl9";

// A user's address. Can be any address
const USER_ADDR: &str = "cosmwasm1zwv6feuzhy6a9wekh96cd57lsarmqlwxdypdum6l3wrwqwax8qts0zj9qp";

mod instantiation {
    use super::*;

    #[test]
    fn instantiate_works() {
        let suite = SuiteBuilder::new().build();

        // Confirm the btc-light-client contract has been instantiated and set
        let config = suite.get_babylon_config();
        assert_eq!(
            config.btc_light_client,
            Some(Addr::unchecked(BTC_LIGHT_CLIENT_CONTRACT_ADDR))
        );
        // Confirm the btc-staking contract has been instantiated and set
        assert_eq!(
            config.btc_staking,
            Some(Addr::unchecked(BTC_STAKING_CONTRACT_ADDR))
        );
        // Confirm the btc-finality contract has been instantiated and set
        assert_eq!(
            config.btc_finality,
            Some(Addr::unchecked(BTC_FINALITY_CONTRACT_ADDR))
        );
        // Check that the btc-staking contract was initialized correctly
        let btc_staking_config = suite.get_btc_staking_config();
        assert_eq!(
            btc_staking_config.babylon,
            Addr::unchecked(BABYLON_CONTRACT_ADDR)
        );
        // Check that the btc-finality contract was initialized correctly
        let btc_finality_config = suite.get_btc_finality_config();
        assert_eq!(
            btc_finality_config.babylon,
            Addr::unchecked(BABYLON_CONTRACT_ADDR)
        );
    }
}

mod finality {
    use super::*;

    use crate::msg::FinalitySignatureResponse;
    use babylon_apis::finality_api::IndexedBlock;
    use test_utils::get_public_randomness_commitment;

    use cosmwasm_std::{coin, Event};
    use test_utils::{
        create_new_finality_provider, get_add_finality_sig, get_derived_btc_delegation,
        get_pub_rand_value,
    };

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
        let initial_funds = &[coin(1_000_000, "TOKEN")];

        let mut suite = SuiteBuilder::new()
            .with_height(initial_height)
            .with_funds(initial_funds)
            .build();

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
            Event::new("sudo").add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
        );

        // Call the end-block sudo handler(s), so that the block is indexed in the store
        let res = suite
            .call_end_block(&add_finality_signature.block_app_hash, initial_height + 1)
            .unwrap();
        assert_eq!(2, res.events.len());
        assert_eq!(
            res.events[0],
            Event::new("sudo").add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
        );
        assert_eq!(
            res.events[1],
            Event::new("wasm-index_block")
                .add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
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
        let initial_funds = &[coin(1_000_000_000_000, "TOKEN")];

        let mut suite = SuiteBuilder::new()
            .with_funds(initial_funds)
            .with_height(initial_height)
            .build();

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
            Event::new("sudo").add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
        );
        assert_eq!(
            res.events[1],
            Event::new("wasm-index_block")
                .add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
                .add_attribute("module", "finality")
                .add_attribute("last_height", submit_height.to_string())
        );
        assert_eq!(
            res.events[2],
            Event::new("wasm-finalize_block")
                .add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
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
    use cosmwasm_std::coin;
    use test_utils::{
        create_new_finality_provider, get_add_finality_sig, get_add_finality_sig_2,
        get_derived_btc_delegation, get_pub_rand_value,
    };

    use crate::multitest::suite::SuiteBuilder;
    use test_utils::get_public_randomness_commitment;

    #[test]
    fn slashing_works() {
        // Read public randomness commitment test data
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
        let pub_rand_one = get_pub_rand_value();
        // Read equivalent / consistent add finality signature test data
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pub_rand.start_height;
        let initial_funds = &[coin(10_000_000_000_000, "TOKEN")];

        let mut suite = SuiteBuilder::new()
            .with_funds(initial_funds)
            .with_height(initial_height)
            .build();

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

mod distribution {
    use babylon_apis::finality_api::IndexedBlock;
    use cosmwasm_std::{coin, Addr};
    use test_utils::{
        create_new_finality_provider, get_add_finality_sig, get_derived_btc_delegation,
        get_pub_rand_value,
    };

    use crate::multitest::suite::SuiteBuilder;
    use test_utils::get_public_randomness_commitment;

    #[test]
    fn distribution_consumer_withdrawal_works() {
        // Read public randomness commitment test data
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
        let pub_rand_one = get_pub_rand_value();
        // Read equivalent / consistent add finality signature test data
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pub_rand.start_height;
        let initial_funds = &[coin(10_000_000_000_000, "TOKEN")];

        let mut suite = SuiteBuilder::new()
            .with_funds(initial_funds)
            .with_height(initial_height)
            .build();

        // Register a couple FPs
        // NOTE: the test data ensures that pub rand commit / finality sig are
        // signed by the 1st FP
        let new_fp1 = create_new_finality_provider(1);
        let new_fp2 = create_new_finality_provider(2);

        suite
            .register_finality_providers(&[new_fp1.clone(), new_fp2.clone()])
            .unwrap();

        // Add a couple delegations, so that the finality providers have some power
        let mut del1 = get_derived_btc_delegation(1, &[1]);
        del1.fp_btc_pk_list = vec![pk_hex.clone()];
        let mut del2 = get_derived_btc_delegation(2, &[2]);
        // Reduce its delegation amount so that the other FP can finalize blocks alone
        del2.total_sat /= 3;

        suite
            .add_delegations(&[del1.clone(), del2.clone()])
            .unwrap();

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

        // Call the end-block sudo handler for completeness / realism
        suite
            .call_end_block(&add_finality_signature.block_app_hash, next_height)
            .unwrap();

        // Call the next block begin blocker, to compute the active FP set
        // FIXME: The second FP is on the active set, and (in the current impl)
        // will get rewards without voting.
        // After offline / inactive detection of FPs (#82) this wouldn't be so bad.
        let next_height = next_height + 1;
        suite.app.advance_blocks(1);
        suite
            .call_begin_block("deadbeef02".as_bytes(), next_height)
            .unwrap();

        // Call the next (final) block end blocker, to process the finality signatures
        suite
            .call_end_block("deadbeef02".as_bytes(), next_height)
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

        // Call the begin / end blocker on an epoch boundary, so that the rewards handler
        // is invoked
        let finality_params = suite.get_btc_finality_params();
        let finality_epoch = finality_params.epoch_length;
        let next_epoch_height = (next_height / finality_epoch + 1) * finality_epoch;
        suite.app.advance_blocks(next_epoch_height - next_height);
        suite
            .call_begin_block("deadbeef03".as_bytes(), next_epoch_height)
            .unwrap();
        suite
            .call_end_block("deadbeef03".as_bytes(), next_epoch_height)
            .unwrap();

        // Assert that rewards have been generated, sent to the staking contract, and
        // distributed among delegators
        let rewards_denom = suite.get_btc_staking_config().denom;
        let staker1_addr = del1.staker_addr;
        let staker2_addr = del2.staker_addr;

        let pending_rewards_1 = suite.get_pending_delegator_rewards(&staker1_addr);
        assert_eq!(pending_rewards_1.len(), 1);
        assert_eq!(pending_rewards_1[0].fp_pubkey_hex, pk_hex);
        assert_eq!(pending_rewards_1[0].rewards.denom, rewards_denom);
        assert!(pending_rewards_1[0].rewards.amount.u128() > 0);

        let pending_rewards_2 = suite.get_pending_delegator_rewards(staker2_addr.as_str());
        assert_eq!(pending_rewards_2.len(), 1);
        assert_eq!(pending_rewards_2[0].fp_pubkey_hex, new_fp2.btc_pk_hex);
        assert_eq!(pending_rewards_2[0].rewards.denom, rewards_denom);
        assert!(pending_rewards_2[0].rewards.amount.u128() > 0);

        // Confirm that the distribution makes sense
        let rewards_1 = pending_rewards_1[0].rewards.amount.u128();
        let rewards_2 = pending_rewards_2[0].rewards.amount.u128();
        assert_eq!(
            rewards_1 / rewards_2,
            del1.total_sat as u128 / del2.total_sat as u128
        );

        // Withdrawing rewards
        // Trying to withdraw the rewards with a Consumer address should fail
        // Build staker 1 address on the Consumer network
        let staker1_addr_consumer = suite
            .to_consumer_addr(&Addr::unchecked(staker1_addr.clone()))
            .unwrap();
        let res = suite.withdraw_rewards(&new_fp1.btc_pk_hex, staker1_addr_consumer.as_ref());
        assert!(res.is_err());

        // Trying to withdraw the rewards with a Babylon address should work
        suite
            .withdraw_rewards(&new_fp1.btc_pk_hex, &staker1_addr)
            .unwrap();

        // Rewards have been transferred out of the staking contract
        let pending_rewards_1 = suite.get_pending_delegator_rewards(staker1_addr.as_str());
        assert_eq!(pending_rewards_1.len(), 1);
        assert_eq!(pending_rewards_1[0].rewards.amount.u128(), 0);

        // And are now in the staker (Consumer's) balance
        let consumer_balance = suite.get_balance(&staker1_addr_consumer, &rewards_denom);
        assert_eq!(consumer_balance.amount.u128(), rewards_1);
    }
}
