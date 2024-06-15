use k256::ecdsa::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};
use k256::sha2::{Digest, Sha256};

use cosmwasm_std::{DepsMut, Env, Response};

use babylon_apis::finality_api::PubRandCommit;
use babylon_bindings::BabylonMsg;
use babylon_merkle::Proof;

use crate::error::ContractError;
use crate::state::config::PARAMS;
use crate::state::finality::SIGNATURES;
use crate::state::public_randomness::{
    get_last_pub_rand_commit, get_pub_rand_commit_for_height, PUB_RAND_COMMITS, PUB_RAND_VALUES,
};
use crate::state::staking::{fps, FPS};

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
    let last_pr_commit = get_last_pub_rand_commit(deps.storage, fp_pubkey_hex).ok();

    if let Some(last_pr_commit) = last_pr_commit {
        // Ensure height and start_height do not overlap, i.e., height < start_height
        let last_pr_end_height = last_pr_commit[0].end_height();
        if start_height <= last_pr_end_height {
            return Err(ContractError::InvalidPubRandHeight(
                start_height,
                last_pr_end_height,
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
    block_hash: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
    // Ensure the finality provider exists
    FPS.load(deps.storage, fp_btc_pk_hex)?;

    // TODO: Ensure the finality provider is not slashed at this time point
    // NOTE: It's possible that the finality provider equivocates for height h, and the signature is
    // processed at height h' > h. In this case:
    // - We should reject any new signature from this finality provider, since it's known to be adversarial.
    // - We should set its voting power since height h'+1 to be zero, for to the same reason.
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
    //     historical block over and over again, making a previous block not finalisable forever.

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
        block_hash,
        signature,
    )?;

    // The public randomness value is good, save it.
    // TODO?: Don't save public randomness values, to save storage space
    PUB_RAND_VALUES.save(deps.storage, (fp_btc_pk_hex, height), &pub_rand.to_vec())?;

    // TODO: Verify whether the voted block is a fork or not
    /*
    indexedBlock, err := ms.GetBlock(ctx, req.BlockHeight)
    if err != nil {
        return nil, err
    }
    if !bytes.Equal(indexedBlock.AppHash, req.BlockAppHash) {
        // the finality provider votes for a fork!

        // construct evidence
        evidence := &types.Evidence{
            FpBtcPk:              req.FpBtcPk,
            BlockHeight:          req.BlockHeight,
            PubRand:              req.PubRand,
            CanonicalAppHash:     indexedBlock.AppHash,
            CanonicalFinalitySig: nil,
            ForkAppHash:          req.BlockAppHash,
            ForkFinalitySig:      signature,
        }

        // if this finality provider has also signed canonical block, slash it
        canonicalSig, err := ms.GetSig(ctx, req.BlockHeight, fpPK)
        if err == nil {
            //set canonical sig
            evidence.CanonicalFinalitySig = canonicalSig
            // slash this finality provider, including setting its voting power to
            // zero, extracting its BTC SK, and emit an event
            ms.slashFinalityProvider(ctx, req.FpBtcPk, evidence)
        }

        // save evidence
        ms.SetEvidence(ctx, evidence)

        // NOTE: we should NOT return error here, otherwise the state change triggered in this tx
        // (including the evidence) will be rolled back
        return &types.MsgAddFinalitySigResponse{}, nil
    }
    */

    // This signature is good, save the vote to the store
    SIGNATURES.save(deps.storage, (height, fp_btc_pk_hex), &signature.to_vec())?;

    // TODO: If this finality provider has signed the canonical block before, slash it via
    // extracting its secret key, and emit an event
    /*
    if ms.HasEvidence(ctx, req.FpBtcPk, req.BlockHeight) {
        // the finality provider has voted for a fork before!
        // If this evidence is at the same height as this signature, slash this finality provider

        // get evidence
        evidence, err := ms.GetEvidence(ctx, req.FpBtcPk, req.BlockHeight)
        if err != nil {
            panic(fmt.Errorf("failed to get evidence despite HasEvidence returns true"))
        }

        // set canonical sig to this evidence
        evidence.CanonicalFinalitySig = signature
        ms.SetEvidence(ctx, evidence)

        // slash this finality provider, including setting its voting power to
        // zero, extracting its BTC SK, and emit an event
        ms.slashFinalityProvider(ctx, req.FpBtcPk, evidence)
    }
    */

    // TODO: Add events
    Ok(Response::new())
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
    let pubkey = eots::PublicKey::from_hex(fp_btc_pk_hex)
        .map_err(|err| ContractError::EotsError(err.to_string()))?;
    let pub_rand = eots::new_pub_rand(pub_rand)
        .map_err(|_| ContractError::EotsError("Failed to parse public randomness".to_string()))?;
    let msg = msg_to_sign(block_height, app_hash);
    let msg_hash = Sha256::digest(msg);

    let signature = eots::new_sig(signature).map_err(ContractError::InvalidSignature)?;

    if !pubkey.verify(
        &pub_rand,
        msg_hash.as_slice().try_into().map_err(|_| {
            ContractError::EotsError("Failed to convert message to array".to_string())
        })?,
        &signature,
    ) {
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

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};

    use crate::contract::tests::{
        create_new_finality_provider, get_public_randomness_commitment, CREATOR,
    };
    use crate::contract::{execute, instantiate};
    use crate::msg::{ExecuteMsg, InstantiateMsg};

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
        let mut new_fp = create_new_finality_provider();
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
}
