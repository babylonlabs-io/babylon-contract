use k256::ecdsa::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};
use k256::sha2::{Digest, Sha256};
use std::cmp::max;
use std::collections::HashSet;

use cosmwasm_std::Order::Ascending;
use cosmwasm_std::{to_json_binary, DepsMut, Env, Event, Response, StdResult, Storage, WasmMsg};

use babylon_apis::finality_api::{Evidence, IndexedBlock, PubRandCommit};
use babylon_bindings::BabylonMsg;
use babylon_merkle::Proof;

use crate::error::ContractError;
use crate::msg::FinalityProviderInfo;
use crate::staking;
use crate::state::config::{CONFIG, PARAMS};
use crate::state::finality::{BLOCKS, EVIDENCES, NEXT_HEIGHT, SIGNATURES};
use crate::state::public_randomness::{
    get_last_pub_rand_commit, get_pub_rand_commit_for_height, PUB_RAND_COMMITS, PUB_RAND_VALUES,
};
use crate::state::staking::{fps, FPS, FP_SET};

pub fn handle_public_randomness_commit(
    deps: DepsMut,
    fp_pubkey_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
    // Ensure the request contains enough amounts of public randomness
    let min_pub_rand = PARAMS.load(deps.storage)?.min_pub_rand;
    if num_pub_rand < min_pub_rand {
        return Err(ContractError::TooFewPubRand(min_pub_rand, num_pub_rand));
    }
    // TODO: ensure log_2(num_pub_rand) is an integer?

    // Ensure the finality provider is registered
    if !FPS.has(deps.storage, fp_pubkey_hex) {
        return Err(ContractError::FinalityProviderNotFound(
            fp_pubkey_hex.to_string(),
        ));
    }
    // Verify signature over the list
    verify_commitment_signature(
        fp_pubkey_hex,
        start_height,
        num_pub_rand,
        commitment,
        signature,
    )?;

    // Get last public randomness commitment
    // TODO: allow committing public randomness earlier than existing ones?
    let last_pr_commit = get_last_pub_rand_commit(deps.storage, fp_pubkey_hex)
        .ok() // Turn error into None
        .flatten();

    // Check for overlapping heights if there is a last commit
    if let Some(last_pr_commit) = last_pr_commit {
        if start_height <= last_pr_commit.end_height() {
            return Err(ContractError::InvalidPubRandHeight(
                start_height,
                last_pr_commit.end_height(),
            ));
        }
    }

    // All good, store the given public randomness commitment
    let pr_commit = PubRandCommit {
        start_height,
        num_pub_rand,
        commitment: commitment.to_vec(),
    };

    PUB_RAND_COMMITS.save(
        deps.storage,
        (fp_pubkey_hex, pr_commit.start_height),
        &pr_commit,
    )?;

    // TODO: Add events
    Ok(Response::new())
}

fn verify_commitment_signature(
    fp_btc_pk_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    // get BTC public key for verification
    let btc_pk_raw = hex::decode(fp_btc_pk_hex)?;
    let btc_pk = VerifyingKey::from_bytes(&btc_pk_raw)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get signature
    if signature.is_empty() {
        return Err(ContractError::EmptySignature);
    }
    let schnorr_sig =
        Signature::try_from(signature).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get signed message
    let mut msg: Vec<u8> = vec![];
    msg.extend_from_slice(&start_height.to_be_bytes());
    msg.extend_from_slice(&num_pub_rand.to_be_bytes());
    msg.extend_from_slice(commitment);

    // Verify the signature
    btc_pk
        .verify(&msg, &schnorr_sig)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn handle_finality_signature(
    deps: DepsMut,
    env: Env,
    fp_btc_pk_hex: &str,
    height: u64,
    pub_rand: &[u8],
    proof: &Proof,
    block_app_hash: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
    // Ensure the finality provider exists
    let fp = FPS.load(deps.storage, fp_btc_pk_hex)?;

    // Ensure the finality provider is not slashed at this time point
    // NOTE: It's possible that the finality provider equivocates for height h, and the signature is
    // processed at height h' > h. In this case:
    // - We should reject any new signature from this finality provider, since it's known to be adversarial.
    // - We should set its voting power since height h'+1 to be zero, for the same reason.
    // - We should NOT set its voting power between [h, h'] to be zero, since
    //   - Babylon BTC staking ensures safety upon 2f+1 votes, *even if* f of them are adversarial.
    //     This is because as long as a block gets 2f+1 votes, any other block with 2f+1 votes has a
    //     f+1 quorum intersection with this block, contradicting the assumption and leading to
    //     the safety proof.
    //     This ensures slashable safety together with EOTS, thus does not undermine Babylon's security guarantee.
    //   - Due to this reason, when tallying a block, Babylon finalises this block upon 2f+1 votes. If we
    //     modify voting power table in the history, some finality decisions might be contradicting to the
    //     signature set and voting power table.
    //   - To fix the above issue, Babylon has to allow finalised and not-finalised blocks. However,
    //     this means Babylon will lose safety under an adaptive adversary corrupting even 1
    //     finality provider. It can simply corrupt a new finality provider and equivocate a
    //     historical block over and over again, making a previous block not finalisable forever
    if fp.slashed_height > 0 && fp.slashed_height < height {
        return Err(ContractError::FinalityProviderAlreadySlashed(
            fp_btc_pk_hex.to_string(),
        ));
    }

    // Ensure the finality provider has voting power at this height
    fps()
        .may_load_at_height(deps.storage, fp_btc_pk_hex, height)?
        .ok_or_else(|| ContractError::NoVotingPower(fp_btc_pk_hex.to_string(), height))?;

    // Ensure the signature is not empty
    if signature.is_empty() {
        return Err(ContractError::EmptySignature);
    }
    // Ensure the height is proper
    if env.block.height < height {
        return Err(ContractError::HeightTooHigh);
    }
    // Ensure the finality provider has not cast the same vote yet
    let existing_sig = SIGNATURES.may_load(deps.storage, (height, fp_btc_pk_hex))?;
    match existing_sig {
        Some(existing_sig) if existing_sig == signature => {
            deps.api.debug(&format!("Received duplicated finality vote. Height: {height}, Finality Provider: {fp_btc_pk_hex}"));
            // Exactly the same vote already exists, return success to the provider
            return Ok(Response::new());
        }
        _ => {}
    }

    // Find the public randomness commitment for this height from this finality provider
    let pr_commit = get_pub_rand_commit_for_height(deps.storage, fp_btc_pk_hex, height)?;

    // Verify the finality signature message
    verify_finality_signature(
        fp_btc_pk_hex,
        height,
        pub_rand,
        proof,
        &pr_commit,
        block_app_hash,
        signature,
    )?;

    // The public randomness value is good, save it.
    // TODO?: Don't save public randomness values, to save storage space
    PUB_RAND_VALUES.save(deps.storage, (fp_btc_pk_hex, height), &pub_rand.to_vec())?;

    // Verify whether the voted block is a fork or not
    // TODO?: Do not rely on 'canonical' (i.e. BFT-consensus provided) blocks info
    let indexed_block = BLOCKS
        .load(deps.storage, height)
        .map_err(|err| ContractError::BlockNotFound(height, err.to_string()))?;

    let mut res = Response::new();
    if indexed_block.app_hash != block_app_hash {
        // The finality provider votes for a fork!

        // Construct evidence
        let mut evidence = Evidence {
            fp_btc_pk: hex::decode(fp_btc_pk_hex)?,
            block_height: height,
            pub_rand: pub_rand.to_vec(),
            canonical_app_hash: indexed_block.app_hash,
            canonical_finality_sig: vec![],
            fork_app_hash: block_app_hash.to_vec(),
            fork_finality_sig: signature.to_vec(),
        };

        // If this finality provider has also signed the canonical block, slash it
        let canonical_sig = SIGNATURES.may_load(deps.storage, (height, fp_btc_pk_hex))?;
        if let Some(canonical_sig) = canonical_sig {
            // Set canonical sig
            evidence.canonical_finality_sig = canonical_sig;
            // Slash this finality provider, including setting its voting power to zero, extracting
            // its BTC SK, and emitting an event
            let (msg, ev) = slash_finality_provider(deps.storage, env, fp_btc_pk_hex, &evidence)?;
            res = res.add_message(msg);
            res = res.add_event(ev);
        }
        // TODO?: Also slash if this finality provider has signed another fork before

        // Save evidence
        EVIDENCES.save(deps.storage, (fp_btc_pk_hex, height), &evidence)?;

        // NOTE: We should NOT return error here, otherwise the state change triggered in this tx
        // (including the evidence) will be rolled back
        return Ok(res);
    }

    // This signature is good, save the vote to the store
    SIGNATURES.save(deps.storage, (height, fp_btc_pk_hex), &signature.to_vec())?;

    // If this finality provider has signed the canonical block before, slash it via extracting its
    // secret key, and emit an event
    if let Some(mut evidence) = EVIDENCES.may_load(deps.storage, (fp_btc_pk_hex, height))? {
        // The finality provider has voted for a fork before!
        // This evidence is at the same height as this signature, slash this finality provider

        // Set canonical sig to this evidence
        evidence.canonical_finality_sig = signature.to_vec();
        EVIDENCES.save(deps.storage, (fp_btc_pk_hex, height), &evidence)?;

        // Slash this finality provider, including setting its voting power to zero, extracting its
        // BTC SK, and emitting an event
        let (msg, ev) = slash_finality_provider(deps.storage, env, fp_btc_pk_hex, &evidence)?;
        res = res.add_message(msg);
        res = res.add_event(ev);
    }

    Ok(res)
}

/// `slash_finality_provider` slashes a finality provider with the given evidence including setting
/// its voting power to zero, extracting its BTC SK, and emitting an event
fn slash_finality_provider(
    store: &mut dyn Storage,
    env: Env,
    fp_btc_pk_hex: &str,
    evidence: &Evidence,
) -> Result<(WasmMsg, Event), ContractError> {
    // Slash this finality provider, i.e., set its slashing height to the block height
    staking::slash_finality_provider(store, env, fp_btc_pk_hex, evidence.block_height)
        .map_err(|err| ContractError::FailedToSlashFinalityProvider(err.to_string()))?;

    // Extract BTC SK using the evidence
    let pk = eots::PublicKey::from_hex(fp_btc_pk_hex).map_err(ContractError::EotsError)?;
    let btc_sk = eots::extract(
        &pk,
        &evidence.pub_rand,
        &evidence.canonical_app_hash,
        &evidence.canonical_finality_sig,
        &evidence.fork_app_hash,
        &evidence.fork_finality_sig,
    )
    .map_err(|err| ContractError::SecretKeyExtractionError(err.to_string()))?;

    // Emit slashing event
    // Raise slashing event to babylon over IBC. Send to babylon-contract for forwarding
    let msg = babylon_contract::ExecuteMsg::Slashing {
        evidence: evidence.clone(),
    };

    let babylon_addr = CONFIG.load(store)?.babylon;

    let wasm_msg = WasmMsg::Execute {
        contract_addr: babylon_addr.to_string(),
        msg: to_json_binary(&msg)?,
        funds: vec![],
    };

    let ev = Event::new("slashed_finality_provider")
        .add_attribute("module", "finality")
        .add_attribute("finality_provider", fp_btc_pk_hex)
        .add_attribute("block_height", evidence.block_height.to_string())
        .add_attribute(
            "canonical_app_hash",
            hex::encode(&evidence.canonical_app_hash),
        )
        .add_attribute(
            "canonical_finality_sig",
            hex::encode(&evidence.canonical_finality_sig),
        )
        .add_attribute("fork_app_hash", hex::encode(&evidence.fork_app_hash))
        .add_attribute(
            "fork_finality_sig",
            hex::encode(&evidence.fork_finality_sig),
        )
        .add_attribute("secret_key", hex::encode(btc_sk.to_bytes()));
    Ok((wasm_msg, ev))
}

/// Verifies the finality signature message w.r.t. the public randomness commitment:
/// - Public randomness inclusion proof.
/// - Finality signature
fn verify_finality_signature(
    fp_btc_pk_hex: &str,
    block_height: u64,
    pub_rand: &[u8],
    proof: &Proof,
    pr_commit: &PubRandCommit,
    app_hash: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    let proof_height = pr_commit.start_height + proof.index;
    if block_height != proof_height {
        return Err(ContractError::InvalidFinalitySigHeight(
            proof_height,
            block_height,
        ));
    }
    // Verify the total amount of randomness is the same as in the commitment
    if proof.total != pr_commit.num_pub_rand {
        return Err(ContractError::InvalidFinalitySigAmount(
            proof.total,
            pr_commit.num_pub_rand,
        ));
    }
    // Verify the proof of inclusion for this public randomness
    proof.validate_basic()?;
    proof.verify(&pr_commit.commitment, pub_rand)?;

    // Public randomness is good, verify finality signature
    let pubkey = eots::PublicKey::from_hex(fp_btc_pk_hex)?;
    let msg = msg_to_sign(block_height, app_hash);
    let msg_hash = Sha256::digest(msg);

    if !pubkey.verify(pub_rand, &msg_hash, signature)? {
        return Err(ContractError::FailedSignatureVerification("EOTS".into()));
    }
    Ok(())
}

/// `msg_to_sign` returns the message for an EOTS signature.
///
/// The EOTS signature on a block will be (block_height || block_hash)
fn msg_to_sign(height: u64, block_hash: &[u8]) -> Vec<u8> {
    let mut msg: Vec<u8> = height.to_be_bytes().to_vec();
    msg.extend_from_slice(block_hash);
    msg
}

pub fn index_block(
    deps: &mut DepsMut,
    height: u64,
    app_hash: &[u8],
) -> Result<Event, ContractError> {
    let indexed_block = IndexedBlock {
        height,
        app_hash: app_hash.into(),
        finalized: false,
    };
    BLOCKS.save(deps.storage, height, &indexed_block)?;

    // Register the indexed block height
    let ev = Event::new("index_block")
        .add_attribute("module", "finality")
        .add_attribute("last_height", height.to_string());
    Ok(ev)
}

/// TallyBlocks tries to finalise all blocks that are non-finalised AND have a non-nil
/// finality provider set, from the earliest to the latest.
///
/// This function is invoked upon each `EndBlock`, after the BTC staking protocol is activated.
/// It ensures that at height `h`, the ancestor chain `[activated_height, h-1]` contains either
/// - finalised blocks (i.e., blocks with a finality provider set AND QC of this finality provider set),
/// - non-finalisable blocks (i.e. blocks with no active finality providers),
/// but no blocks that have a finality provider set and do not receive a QC
///
/// It must be invoked only after the BTC staking protocol is activated.
pub fn tally_blocks(
    deps: &mut DepsMut,
    activated_height: u64,
    height: u64,
) -> Result<Vec<Event>, ContractError> {
    // Start finalising blocks since max(activated_height, next_height)
    let next_height = NEXT_HEIGHT.may_load(deps.storage)?.unwrap_or(0);
    let start_height = max(activated_height, next_height);

    // Find all blocks that are non-finalised AND have a finality provider set since
    // max(activated_height, last_finalized_height + 1)
    // There are 4 different scenarios:
    // - Has finality providers, non-finalised: Tally and try to finalise.
    // - Does not have finality providers, non-finalised: Non-finalisable, continue.
    // - Has finality providers, finalised: Impossible, panic.
    // - Does not have finality providers, finalised: Impossible, panic.
    // After this for loop, the blocks since the earliest activated height are either finalised or
    // non-finalisable
    let mut events = vec![];
    for h in start_height..=height {
        let mut indexed_block = BLOCKS.load(deps.storage, h)?;
        // Get the finality provider set of this block
        let fp_set = FP_SET.may_load(deps.storage, h)?;

        match (fp_set, indexed_block.finalized) {
            (Some(fp_set), false) => {
                // Has finality providers, non-finalised: tally and try to finalise the block
                let voter_btc_pks = SIGNATURES
                    .prefix(indexed_block.height)
                    .keys(deps.storage, None, None, Ascending)
                    .collect::<StdResult<Vec<_>>>()?;
                if tally(&fp_set, &voter_btc_pks) {
                    // If this block gets >2/3 votes, finalise it
                    let ev = finalize_block(deps.storage, &mut indexed_block, &voter_btc_pks)?;
                    events.push(ev);
                } else {
                    // If not, then this block and all subsequent blocks should not be finalised.
                    // Thus, we need to break here
                    break;
                }
            }
            (None, false) => {
                // Does not have finality providers, non-finalised: not finalisable,
                // Increment the next height to finalise and continue
                NEXT_HEIGHT.save(deps.storage, &(indexed_block.height + 1))?;
                continue;
            }
            (Some(_), true) => {
                // Has finality providers and the block is finalised.
                // This can only be a programming error
                return Err(ContractError::FinalisedBlockWithFinalityProviderSet(
                    indexed_block.height,
                ));
            }
            (None, true) => {
                // Does not have finality providers, finalised: impossible to happen
                return Err(ContractError::FinalisedBlockWithoutFinalityProviderSet(
                    indexed_block.height,
                ));
            }
        }
    }
    Ok(events)
}

/// `tally` checks whether a block with the given finality provider set and votes reaches a quorum
/// or not
fn tally(fp_set: &[FinalityProviderInfo], voters: &[String]) -> bool {
    let voters: HashSet<String> = voters.iter().cloned().collect();
    let mut total_power = 0;
    let mut voted_power = 0;
    for fp_info in fp_set {
        total_power += fp_info.power;
        if voters.contains(&fp_info.btc_pk_hex) {
            voted_power += fp_info.power;
        }
    }
    voted_power * 3 > total_power * 2
}

/// `finalize_block` sets a block to be finalised, and distributes rewards to finality providers
/// and delegators
fn finalize_block(
    store: &mut dyn Storage,
    block: &mut IndexedBlock,
    _voters: &[String],
) -> Result<Event, ContractError> {
    // Set block to be finalised
    block.finalized = true;
    BLOCKS.save(store, block.height, block)?;

    // Set the next height to finalise as height+1
    NEXT_HEIGHT.save(store, &(block.height + 1))?;

    // TODO: Distribute rewards to BTC staking delegators

    // Record the last finalized height metric
    let ev = Event::new("finalize_block")
        .add_attribute("module", "finality")
        .add_attribute("finalized_height", block.height.to_string());
    Ok(ev)
}

#[cfg(test)]
pub(crate) mod tests {
    use babylon_apis::btc_staking_api::SudoMsg;
    use babylon_apis::finality_api::IndexedBlock;
    use babylon_bindings::BabylonMsg;
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{to_json_binary, Binary, Env, Event, OwnedDeps, Response, SubMsg, WasmMsg};
    use hex::ToHex;
    use test_utils::{get_add_finality_sig, get_add_finality_sig_2, get_pub_rand_value};

    use crate::contract::tests::{
        create_new_finality_provider, get_public_randomness_commitment, CREATOR,
    };
    use crate::contract::{execute, instantiate};
    use crate::msg::{ExecuteMsg, FinalitySignatureResponse, InstantiateMsg};

    pub(crate) fn mock_env_height(height: u64) -> Env {
        let mut env = mock_env();
        env.block.height = height;

        env
    }

    #[track_caller]
    pub(crate) fn call_begin_block(
        deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier>,
        app_hash: &[u8],
        height: u64,
    ) -> Result<Response<BabylonMsg>, crate::error::ContractError> {
        let env = mock_env_height(height);
        // Hash is not used in the begin-block handler
        let hash_hex = "deadbeef".to_string();
        let app_hash_hex = app_hash.encode_hex();

        crate::contract::sudo(
            deps.as_mut(),
            env.clone(),
            SudoMsg::BeginBlock {
                hash_hex,
                app_hash_hex,
            },
        )
    }

    #[track_caller]
    pub(crate) fn call_end_block(
        deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier>,
        app_hash: &[u8],
        height: u64,
    ) -> Result<Response<BabylonMsg>, crate::error::ContractError> {
        let env = mock_env_height(height);
        // Hash is not used in the begin-block handler
        let hash_hex = "deadbeef".to_string();
        let app_hash_hex = app_hash.encode_hex();

        crate::contract::sudo(
            deps.as_mut(),
            env.clone(),
            SudoMsg::EndBlock {
                hash_hex,
                app_hash_hex,
            },
        )
    }

    #[test]
    fn commit_public_randomness_works() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Read public randomness commitment test data
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();

        // Register one FP with a valid pubkey first
        let mut new_fp = create_new_finality_provider(1);
        new_fp.btc_pk_hex.clone_from(&pk_hex);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Now commit the public randomness for it
        let msg = ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex: pk_hex,
            start_height: pub_rand.start_height,
            num_pub_rand: pub_rand.num_pub_rand,
            commitment: pub_rand.commitment.into(),
            signature: pubrand_signature.into(),
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn finality_signature_happy_path() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Read public randomness commitment test data
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
        let pub_rand_one = get_pub_rand_value();
        // Read equivalent / consistent add finality signature test data
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pub_rand.start_height;

        let initial_env = mock_env_height(initial_height);

        instantiate(
            deps.as_mut(),
            initial_env.clone(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Register one FP with a valid pubkey first
        let mut new_fp = create_new_finality_provider(1);
        new_fp.btc_pk_hex.clone_from(&pk_hex);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), initial_env.clone(), info.clone(), msg).unwrap();

        // Activated height is not set
        let res = crate::queries::activated_height(deps.as_ref()).unwrap();
        assert_eq!(res.height, 0);

        // Add a delegation, so that the finality provider has some power
        let mut del1 = crate::contract::tests::get_derived_btc_delegation(1, &[]);
        del1.fp_btc_pk_list = vec![pk_hex.clone()];

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), initial_env, info.clone(), msg).unwrap();

        // Activated height is now set
        let activated_height = crate::queries::activated_height(deps.as_ref()).unwrap();
        assert_eq!(activated_height.height, initial_height + 1);

        // Submit public randomness commitment for the FP and the involved heights
        let msg = ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex: pk_hex.clone(),
            start_height: pub_rand.start_height,
            num_pub_rand: pub_rand.num_pub_rand,
            commitment: pub_rand.commitment.into(),
            signature: pubrand_signature.into(),
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Call the begin-block sudo handler, for completeness
        let res = call_begin_block(
            &mut deps,
            &add_finality_signature.block_app_hash,
            initial_height + 1,
        )
        .unwrap();
        assert_eq!(0, res.attributes.len());
        assert_eq!(0, res.messages.len());
        assert_eq!(0, res.events.len());

        // Call the end-block sudo handler, so that the block is indexed in the store
        let res = call_end_block(
            &mut deps,
            &add_finality_signature.block_app_hash,
            initial_height + 1,
        )
        .unwrap();
        assert_eq!(0, res.attributes.len());
        assert_eq!(0, res.messages.len());
        assert_eq!(1, res.events.len());
        assert_eq!(
            res.events[0],
            Event::new("index_block")
                .add_attribute("module", "finality")
                .add_attribute("last_height", (initial_height + 1).to_string())
        );

        // Submit a finality signature from that finality provider at height initial_height + 1
        let finality_signature = add_finality_signature.finality_sig.to_vec();
        let msg = ExecuteMsg::SubmitFinalitySignature {
            fp_pubkey_hex: pk_hex.clone(),
            height: initial_height + 1,
            pub_rand: pub_rand_one.into(),
            proof: proof.into(),
            block_hash: add_finality_signature.block_app_hash.to_vec().into(),
            signature: Binary::new(finality_signature.clone()),
        };

        // Execute the message at a higher height, so that:
        // 1. It's not rejected because of height being too high.
        // 2. The FP has consolidated power at such height
        let _res = execute(
            deps.as_mut(),
            mock_env_height(initial_height + 2),
            info.clone(),
            msg,
        )
        .unwrap();

        // Query finality signature for that exact height
        let sig = crate::queries::finality_signature(
            deps.as_ref(),
            pk_hex.to_string(),
            initial_height + 1,
        )
        .unwrap();
        assert_eq!(
            sig,
            FinalitySignatureResponse {
                signature: finality_signature
            }
        );
    }

    #[test]
    fn finality_round_works() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Read public randomness commitment test data
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
        let pub_rand_one = get_pub_rand_value();
        // Read equivalent / consistent add finality signature test data
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pub_rand.start_height;

        let initial_env = mock_env_height(initial_height);

        instantiate(
            deps.as_mut(),
            initial_env.clone(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Register one FP with a valid pubkey first
        let mut new_fp = create_new_finality_provider(1);
        new_fp.btc_pk_hex.clone_from(&pk_hex);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), initial_env.clone(), info.clone(), msg).unwrap();

        // Add a delegation, so that the finality provider has some power
        let mut del1 = crate::contract::tests::get_derived_btc_delegation(1, &[]);
        del1.fp_btc_pk_list = vec![pk_hex.clone()];

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), initial_env, info.clone(), msg).unwrap();

        // Submit public randomness commitment for the FP and the involved heights
        let msg = ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex: pk_hex.clone(),
            start_height: pub_rand.start_height,
            num_pub_rand: pub_rand.num_pub_rand,
            commitment: pub_rand.commitment.into(),
            signature: pubrand_signature.into(),
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Call the begin-block sudo handler, for completeness
        let res = call_begin_block(
            &mut deps,
            &add_finality_signature.block_app_hash,
            initial_height + 1,
        )
        .unwrap();
        assert_eq!(0, res.attributes.len());
        assert_eq!(0, res.messages.len());
        assert_eq!(0, res.events.len());

        // Call the end-block sudo handler, so that the block is indexed in the store
        let res = call_end_block(
            &mut deps,
            &add_finality_signature.block_app_hash,
            initial_height + 1,
        )
        .unwrap();
        assert_eq!(0, res.attributes.len());
        assert_eq!(0, res.messages.len());
        assert_eq!(1, res.events.len());
        assert_eq!(
            res.events[0],
            Event::new("index_block")
                .add_attribute("module", "finality")
                .add_attribute("last_height", (initial_height + 1).to_string())
        );

        // Submit a finality signature from that finality provider at height initial_height + 1
        let submit_height = initial_height + 1;
        let finality_signature = add_finality_signature.finality_sig.to_vec();
        let msg = ExecuteMsg::SubmitFinalitySignature {
            fp_pubkey_hex: pk_hex.clone(),
            height: submit_height,
            pub_rand: pub_rand_one.into(),
            proof: proof.into(),
            block_hash: add_finality_signature.block_app_hash.to_vec().into(),
            signature: Binary::new(finality_signature.clone()),
        };

        // Execute the message at the exact submit height, so that:
        // 1. It's not rejected because of height being too high.
        // 2. The FP has consolidated power at such height
        // 3. There are no more pending / future blocks to process
        let submit_env = mock_env_height(submit_height);
        let _res = execute(deps.as_mut(), submit_env.clone(), info.clone(), msg).unwrap();

        // Call the begin blocker, to compute the active FP set
        let res = call_begin_block(
            &mut deps,
            &add_finality_signature.block_app_hash,
            submit_height,
        )
        .unwrap();
        assert_eq!(0, res.attributes.len());
        assert_eq!(0, res.events.len());
        assert_eq!(0, res.messages.len());

        // Call the end blocker, to process the finality signatures
        let res = call_end_block(
            &mut deps,
            &add_finality_signature.block_app_hash,
            submit_height,
        )
        .unwrap();
        assert_eq!(0, res.attributes.len());
        assert_eq!(2, res.events.len());
        assert_eq!(
            res.events[0],
            Event::new("index_block")
                .add_attribute("module", "finality")
                .add_attribute("last_height", submit_height.to_string())
        );
        assert_eq!(
            res.events[1],
            Event::new("finalize_block")
                .add_attribute("module", "finality")
                .add_attribute("finalized_height", submit_height.to_string())
        );
        assert_eq!(0, res.messages.len());

        // Assert the submitted block has been indexed and finalised
        let indexed_block = crate::queries::block(deps.as_ref(), submit_height).unwrap();
        assert_eq!(
            indexed_block,
            IndexedBlock {
                height: submit_height,
                app_hash: add_finality_signature.block_app_hash.to_vec(),
                finalized: true,
            }
        );
    }

    #[test]
    fn slashing_works() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Read public randomness commitment test data
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
        let pub_rand_one = get_pub_rand_value();
        // Read equivalent / consistent add finality signature test data
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pub_rand.start_height;
        let initial_env = mock_env_height(initial_height);

        instantiate(
            deps.as_mut(),
            initial_env.clone(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: None,
            },
        )
        .unwrap();

        // Register one FP with a valid pubkey first
        let mut new_fp = create_new_finality_provider(1);
        new_fp.btc_pk_hex.clone_from(&pk_hex);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), initial_env.clone(), info.clone(), msg).unwrap();

        // Add a delegation, so that the finality provider has some power
        let mut del1 = crate::contract::tests::get_derived_btc_delegation(1, &[]);
        del1.fp_btc_pk_list = vec![pk_hex.clone()];

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), initial_env.clone(), info.clone(), msg).unwrap();

        // Submit public randomness commitment for the FP and the involved heights
        let msg = ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex: pk_hex.clone(),
            start_height: pub_rand.start_height,
            num_pub_rand: pub_rand.num_pub_rand,
            commitment: pub_rand.commitment.into(),
            signature: pubrand_signature.into(),
        };

        execute(deps.as_mut(), initial_env, info.clone(), msg).unwrap();

        // Call the begin-block sudo handler at the next height, for completeness
        let next_height = initial_height + 1;
        call_begin_block(
            &mut deps,
            &add_finality_signature.block_app_hash,
            next_height,
        )
        .unwrap();

        // Call the end-block sudo handler, so that the block is indexed in the store
        call_end_block(
            &mut deps,
            &add_finality_signature.block_app_hash,
            next_height,
        )
        .unwrap();

        // Submit a finality signature from that finality provider at next height (initial_height + 1)
        let submit_height = next_height;
        // Increase block height
        let next_height = next_height + 1;
        let next_env = mock_env_height(next_height);
        // Call the begin-block sudo handler at the next height, for completeness
        call_begin_block(&mut deps, "deadbeef01".as_bytes(), next_height).unwrap();

        let finality_signature = add_finality_signature.finality_sig.to_vec();
        let msg = ExecuteMsg::SubmitFinalitySignature {
            fp_pubkey_hex: pk_hex.clone(),
            height: submit_height,
            pub_rand: pub_rand_one.clone().into(),
            proof: proof.clone().into(),
            block_hash: add_finality_signature.block_app_hash.to_vec().into(),
            signature: Binary::new(finality_signature.clone()),
        };

        let res = execute(deps.as_mut(), next_env.clone(), info.clone(), msg.clone()).unwrap();
        assert_eq!(0, res.messages.len());
        assert_eq!(0, res.events.len());

        // Submitting the same signature twice is tolerated
        let res = execute(deps.as_mut(), next_env.clone(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());
        assert_eq!(0, res.events.len());

        // Submit another (different and valid) finality signature, from the same finality provider
        // at the same height
        let add_finality_signature_2 = get_add_finality_sig_2();
        let msg = ExecuteMsg::SubmitFinalitySignature {
            fp_pubkey_hex: pk_hex.clone(),
            height: submit_height,
            pub_rand: pub_rand_one.into(),
            proof: proof.into(),
            block_hash: add_finality_signature_2.block_app_hash.to_vec().into(),
            signature: Binary::new(add_finality_signature_2.finality_sig.to_vec()),
        };
        let res = execute(deps.as_mut(), next_env.clone(), info.clone(), msg).unwrap();

        // Assert the double signing evidence is proper
        let btc_pk = hex::decode(pk_hex.clone()).unwrap();
        let evidence = crate::queries::evidence(deps.as_ref(), pk_hex.clone(), submit_height)
            .unwrap()
            .evidence
            .unwrap();
        assert_eq!(evidence.block_height, submit_height);
        assert_eq!(evidence.fp_btc_pk, btc_pk);

        // Assert the slashing propagation msg is there
        assert_eq!(1, res.messages.len());
        // Assert the slashing propagation msg is proper
        let babylon_addr = crate::queries::config(deps.as_ref()).unwrap().babylon;
        assert_eq!(
            res.messages[0],
            SubMsg::new(WasmMsg::Execute {
                contract_addr: babylon_addr.to_string(),
                msg: to_json_binary(&babylon_contract::ExecuteMsg::Slashing { evidence }).unwrap(),
                funds: vec![]
            })
        );
        // Assert the slashing event is there
        assert_eq!(1, res.events.len());
        // Assert the slashing event is proper
        assert_eq!(res.events[0].ty, "slashed_finality_provider".to_string());

        // Call the end-block sudo handler for completeness / realism
        call_end_block(&mut deps, "deadbeef01".as_bytes(), next_height).unwrap();

        // Call the next (final) block begin blocker, to compute the active FP set
        let final_height = next_height + 1;
        call_begin_block(&mut deps, "deadbeef02".as_bytes(), final_height).unwrap();

        // Call the next (final) block end blocker, to process the finality signatures
        call_end_block(&mut deps, "deadbeef02".as_bytes(), final_height).unwrap();

        // Assert the canonical block has been indexed (and finalised)
        let indexed_block = crate::queries::block(deps.as_ref(), submit_height).unwrap();
        assert_eq!(
            indexed_block,
            IndexedBlock {
                height: submit_height,
                app_hash: add_finality_signature.block_app_hash.to_vec(),
                finalized: true,
            }
        );

        // Assert the finality provider has been slashed
        let fp = crate::queries::finality_provider(deps.as_ref(), pk_hex).unwrap();
        assert_eq!(fp.slashed_height, submit_height);
    }
}
