use std::collections::HashSet;

use crate::error::ContractError;
use crate::queries::query_last_pub_rand_commit;
use crate::state::config::CONFIG;
use crate::state::finality::{BLOCK_VOTES, SIGNATURES};
use crate::state::public_randomness::{
    get_pub_rand_commit_for_height, PUB_RAND_COMMITS, PUB_RAND_VALUES,
};
use crate::utils::query_finality_provider;

use babylon_apis::finality_api::PubRandCommit;
use babylon_merkle::Proof;
use cosmwasm_std::{Deps, DepsMut, Env, Event, Response};
use k256::ecdsa::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};
use k256::sha2::{Digest, Sha256};
use eots::EotsError;

// Most logic copied from contracts/btc-staking/src/finality.rs
pub fn handle_public_randomness_commit(
    deps: DepsMut,
    fp_pubkey_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<Response, ContractError> {
    // Ensure the finality provider is registered
    check_fp_exist(deps.as_ref(), fp_pubkey_hex)?;

    // TODO: ensure log_2(num_pub_rand) is an integer?

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
    let last_pr_commit = query_last_pub_rand_commit(deps.storage, fp_pubkey_hex)?;

    if let Some(last_pr_commit) = last_pr_commit {
        // Ensure height and start_height do not overlap, i.e., height < start_height
        let last_pr_end_height = last_pr_commit.end_height();
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

    let event = Event::new("public_randomness_commit")
        .add_attribute("fp_pubkey_hex", fp_pubkey_hex)
        .add_attribute("pr_commit.start_height", pr_commit.start_height.to_string())
        .add_attribute("pr_commit.num_pub_rand", pr_commit.num_pub_rand.to_string());

    Ok(Response::new().add_event(event))
}

// Copied from contracts/btc-staking/src/finality.rs
pub(crate) fn verify_commitment_signature(
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

// Most logic copied from contracts/btc-staking/src/finality.rs
#[allow(clippy::too_many_arguments)]
pub fn handle_finality_signature(
    deps: DepsMut,
    _env: Env,
    fp_btc_pk_hex: &str,
    height: u64,
    pub_rand: &[u8],
    proof: &Proof,
    block_hash: &[u8],
    signature: &[u8],
) -> Result<Response, ContractError> {
    // Ensure the finality provider exists
    check_fp_exist(deps.as_ref(), fp_btc_pk_hex)?;

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
    // TODO (lester): use gRPC to query the Babylon Chain

    // Ensure the signature is not empty
    if signature.is_empty() {
        return Err(ContractError::EmptySignature);
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

    // Check if the key (height, block_hash) exists
    let mut block_votes_fp_set = BLOCK_VOTES
        .may_load(deps.storage, (height, block_hash))?
        .unwrap_or_else(HashSet::new);

    // Add the fp_btc_pk_hex to the set
    block_votes_fp_set.insert(fp_btc_pk_hex.to_string());

    // Save the updated set back to storage
    BLOCK_VOTES.save(deps.storage, (height, block_hash), &block_votes_fp_set)?;

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

    let event = Event::new("submit_finality_signature")
        .add_attribute("fp_pubkey_hex", fp_btc_pk_hex)
        .add_attribute("block_height", height.to_string())
        .add_attribute("block_hash", hex::encode(block_hash));

    Ok(Response::new().add_event(event))
}

/// Verifies the finality signature message w.r.t. the public randomness commitment:
/// - Public randomness inclusion proof.
/// - Finality signature
pub(crate) fn verify_finality_signature(
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
    let pub_rand = eots::new_pub_rand(pub_rand)?;
    let msg = msg_to_sign(block_height, app_hash);
    let msg_hash = Sha256::digest(msg);

    let signature = eots::new_sig(signature)?;

    if !pubkey.verify(
        &pub_rand,
        msg_hash.as_slice().try_into()
            .map_err(|_| ContractError::EotsError(EotsError::InvalidInputLength(msg_hash.len())))?,
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

fn check_fp_exist(deps: Deps, fp_pubkey_hex: &str) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let fp = query_finality_provider(deps, config.consumer_id.clone(), fp_pubkey_hex.to_string());
    match fp {
        Ok(_value) => {
            // TODO: check the slash
            // value.slashed_babylon_height != value.height;
            Ok(())
        }
        Err(_e) => Err(ContractError::NotFoundFinalityProvider(
            config.consumer_id,
            fp_pubkey_hex.to_string(),
        )),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use babylon_apis::finality_api::PubRandCommit;
    use hex::ToHex;
    use test_utils::{get_add_finality_sig, get_pub_rand_commit, get_pub_rand_value};

    /// Get public randomness public key, commitment, and signature information
    ///
    /// Signature is a Schnorr signature over the commitment
    pub(crate) fn get_public_randomness_commitment() -> (String, PubRandCommit, Vec<u8>) {
        let pub_rand_commitment_msg = get_pub_rand_commit();
        (
            pub_rand_commitment_msg.fp_btc_pk.encode_hex(),
            PubRandCommit {
                start_height: pub_rand_commitment_msg.start_height,
                num_pub_rand: pub_rand_commitment_msg.num_pub_rand,
                commitment: pub_rand_commitment_msg.commitment.to_vec(),
            },
            pub_rand_commitment_msg.sig.to_vec(),
        )
    }

    #[test]
    fn verify_commitment_signature_works() {
        // Define test values
        let (fp_btc_pk_hex, pr_commit, sig) = get_public_randomness_commitment();

        // Verify commitment signature
        let res = verify_commitment_signature(
            &fp_btc_pk_hex,
            pr_commit.start_height,
            pr_commit.num_pub_rand,
            &pr_commit.commitment,
            &sig,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn verify_finality_signature_works() {
        // Read public randomness commitment test data
        let (pk_hex, pr_commit, _) = get_public_randomness_commitment();
        let pub_rand_one = get_pub_rand_value();
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pr_commit.start_height;

        // Verify finality signature
        if proof.index < 0 {
            panic!("Proof index should be non-negative");
        }
        let res = verify_finality_signature(
            &pk_hex,
            initial_height + proof.index.unsigned_abs(),
            &pub_rand_one,
            // we need to add a typecast below because the provided proof is of type
            // tendermint_proto::crypto::Proof, whereas the fn expects babylon_merkle::proof
            &proof.into(),
            &pr_commit,
            &add_finality_signature.block_app_hash,
            &add_finality_signature.finality_sig,
        );
        assert!(res.is_ok());
    }
}
