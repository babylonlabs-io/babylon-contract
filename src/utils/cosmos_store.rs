// the below keys are hard-coded for now. They have to be consistent with the Babylon repo.
// TODO: integration tests for ensuring them are same, or parameterise them upon instantiation
// https://github.com/babylonchain/babylon/blob/v0.5.0/x/epoching/types/keys.go#L8
pub const EPOCHING_STORE_KEY: &[u8] = b"epoching";
// https://github.com/babylonchain/babylon/blob/v0.5.0/x/checkpointing/types/keys.go#L13
pub const CHECKPOINTING_STORE_KEY: &[u8] = b"checkpointing";

pub fn get_epoch_info_key(epoch_number: u64) -> Vec<u8> {
    // see https://github.com/babylonchain/babylon/blob/v0.5.0/x/epoching/types/keys.go#L22
    let mut epoch_info_key = [0x12].to_vec();
    epoch_info_key.extend(epoch_number.to_be_bytes());
    return epoch_info_key;
}

pub fn get_valset_key(epoch_number: u64) -> Vec<u8> {
    // see https://github.com/babylonchain/babylon/blob/v0.5.0/x/checkpointing/types/keys.go#L28
    let mut epoch_info_key = [0x3].to_vec();
    epoch_info_key.extend(epoch_number.to_be_bytes());
    return epoch_info_key;
}

pub fn verify_store(
    root: &[u8],
    module_key: &[u8],
    key: &[u8],
    value: &[u8],
    proof: tendermint_proto::crypto::ProofOps,
) -> Result<(), String> {
    // convert tendermint_proto::crypto::ProofOps to ics23 proof
    let ics23_proof_res =
        crate::utils::ics23_commitment::merkle::convert_tm_proto_to_ics_merkle_proof(&proof);
    if ics23_proof_res.is_err() {
        return Err("failed to convert tendermint_proto::crypto::ProofOps to ibc::core::ics23_commitment::merkle::MerkleProof".to_string());
    }
    let ics23_proof = ics23_proof_res.unwrap();

    // construct values for verifying Merkle proofs
    let specs = crate::utils::ics23_commitment::specs::ProofSpecs::default();
    let merkle_root = root.to_vec();
    let merkle_keys = vec![module_key.to_vec(), key.to_vec()];

    // verify
    let verify_res =
        ics23_proof.verify_membership(&specs, merkle_root, merkle_keys, value.to_vec(), 0);
    if verify_res.is_err() {
        println!("{:?}", verify_res);
        return Err("failed to verify Tendermint Merkle proof".to_string());
    }

    Ok(())
}
