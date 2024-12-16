use crate::utils::ics23_commitment::merkle::convert_tm_proto_to_ics_merkle_proof;

// the below keys are hard-coded for now. They have to be consistent with the Babylon repo.
// TODO: integration tests for ensuring they are the same, or parametrise them upon instantiation
// https://github.com/babylonlabs-io/babylon/blob/v0.8.0-rc.0/x/epoching/types/keys.go
#[cfg(feature = "btc-lc")]
pub const EPOCHING_STORE_KEY: &[u8] = b"epoching";
// https://github.com/babylonlabs-io/babylon/blob/v0.8.0-rc.0/x/checkpointing/types/keys.go
#[cfg(feature = "btc-lc")]
pub const CHECKPOINTING_STORE_KEY: &[u8] = b"checkpointing";
// #[cfg(feature = "btc-lc")]
// https://github.com/babylonlabs-io/babylon/blob/v0.8.0-rc.0/x/zoneconcierge/types/keys.go
pub const ZONECONCIERGE_STORE_KEY: &[u8] = b"zoneconcierge";

#[cfg(feature = "btc-lc")]
pub fn get_epoch_info_key(epoch_number: u64) -> Vec<u8> {
    // https://github.com/babylonlabs-io/babylon/blob/8638c950fd2de1ac5dc69a8b9f710c1fa720c155/x/epoching/types/keys.go#L21
    let mut epoch_info_key = [0x11].to_vec();
    epoch_info_key.extend(epoch_number.to_be_bytes());
    epoch_info_key
}

#[cfg(feature = "btc-lc")]
pub fn get_valset_key(epoch_number: u64) -> Vec<u8> {
    // https://github.com/babylonlabs-io/babylon/blob/8638c950fd2de1ac5dc69a8b9f710c1fa720c155/x/checkpointing/types/keys.go#L28
    let mut epoch_valset_key = [0x03].to_vec();
    epoch_valset_key.extend(epoch_number.to_be_bytes());
    epoch_valset_key
}

pub fn get_cz_header_key(chain_id: &String, height: u64) -> Vec<u8> {
    // https://github.com/babylonlabs-io/babylon/blob/8638c950fd2de1ac5dc69a8b9f710c1fa720c155/x/zoneconcierge/types/keys.go#L33
    let mut key = [0x13].to_vec();
    key.extend(chain_id.as_bytes());
    key.extend(height.to_be_bytes());
    key
}

pub fn verify_store(
    root: &[u8],
    module_key: &[u8],
    key: &[u8],
    value: &[u8],
    proof: &tendermint_proto::crypto::ProofOps,
) -> Result<(), String> {
    // convert tendermint_proto::crypto::ProofOps to ics23 proof
    let ics23_proof = convert_tm_proto_to_ics_merkle_proof(proof)
        .map_err(|err|format!("failed to convert tendermint_proto::crypto::ProofOps to ibc::core::ics23_commitment::merkle::MerkleProof: {err:?}"))?;

    // construct values for verifying Merkle proofs
    let specs = crate::utils::ics23_commitment::specs::ProofSpecs::default();
    let merkle_root = root.to_vec();
    let merkle_keys = vec![module_key.to_vec(), key.to_vec()];

    // verify
    ics23_proof
        .verify_membership(&specs, merkle_root, merkle_keys, value.to_vec(), 0)
        .map_err(|err| format!("failed to verify Tendermint Merkle proof: {err:?}"))?;

    Ok(())
}
