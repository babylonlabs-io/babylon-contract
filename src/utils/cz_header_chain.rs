use crate::error;
use sha2::{Digest, Sha256};
use tendermint::hash::Hash;
use tendermint_proto::crypto::Proof;
use tendermint_proto::types::TxProof;

/// verify_tx_in_block verifies whether a tx with tx_hash is committed to
/// the Merkle root hash of a Tendermint block
pub fn verify_tx_in_block(
    tx_hash: &[u8],
    root_hash: &[u8],
    proof_tx_in_block: &TxProof,
) -> Result<(), error::CZHeaderChainError> {
    if proof_tx_in_block.root_hash.ne(root_hash) {
        return Err(error::CZHeaderChainError::TxProofError {});
    }
    let proto_proof = proof_tx_in_block
        .proof
        .clone()
        .ok_or(error::CZHeaderChainError::TxProofError {})?;
    let proof = tendermint::merkle::Proof::try_from(proto_proof)
        .map_err(|_| error::CZHeaderChainError::TxProofError {})?;

    verify_tm_merkle_proof(&proof, root_hash, tx_hash)
        .map_err(|_| error::CZHeaderChainError::TxProofError {})
}

/// verify_block_in_epoch verifies whether the header with header_app_hash is committed
/// to the Merkle root app_hash_root of an epoch
pub fn verify_block_in_epoch(
    header_app_hash: &[u8],
    app_hash_root: &[u8],
    proof_header_in_epoch: &Proof,
) -> Result<(), error::CZHeaderChainError> {
    let merkle_proof = tendermint::merkle::Proof::try_from(proof_header_in_epoch.clone())
        .map_err(|_| error::CZHeaderChainError::TxProofDecodeError {})?;

    let verify_res = verify_tm_merkle_proof(&merkle_proof, app_hash_root, header_app_hash);
    if verify_res.is_err() {
        return Err(error::CZHeaderChainError::TxProofError {});
    }

    Ok(())
}

/// verify_tm_merkle_proof verifies whether the leaf is committed to the root_hash of a Merkle tree
/// (ported from https://github.com/cometbft/cometbft/blob/v0.37.0/crypto/merkle/proof.go#L52-L68)
fn verify_tm_merkle_proof(
    proof: &tendermint::merkle::Proof,
    root_hash: &[u8],
    leaf: &[u8],
) -> Result<(), String> {
    let leaf_hash = leaf_hash(leaf);
    if proof.total == 0 {
        return Err("proof total must be positive".into());
    }
    if proof.leaf_hash.ne(&leaf_hash) {
        return Err(format!(
            "invalid leaf hash: wanted {:X?} got {:X?}",
            leaf_hash, proof.leaf_hash
        ));
    }
    let computed_hash = compute_root_hash(proof);
    if computed_hash != root_hash {
        return Err(format!(
            "invalid root hash: wanted {root_hash:X?} got {computed_hash:X?}"
        ));
    }
    Ok(())
}

fn compute_root_hash(proof: &tendermint::merkle::Proof) -> Vec<u8> {
    compute_hash_from_aunts(proof.index, proof.total, &proof.leaf_hash, &proof.aunts)
}

/// compute_hash_from_aunts computes a Merkle root given a leaf hash, a list
/// of inner hashes, and the total number of leaves in the Merkle tree.
///
/// The algorithm works recursively by traversing the tree from leaf to root.
/// At each level, it uses the index of the current leaf node and the
/// total number of nodes to determine which subtree to traverse.
/// It then computes the hash of the left and right subtrees by recursively
/// calling itself with the appropriate parameters.
/// Finally, it computes the inner hash of the left and right hashes.
/// (ported from https://github.com/cometbft/cometbft/blob/v0.37.0/crypto/merkle/proof.go#L148-L181)
fn compute_hash_from_aunts(
    index: u64,
    total: u64,
    leaf_hash: &Hash,
    inner_hashes: &[Hash],
) -> Vec<u8> {
    if index >= total || total == 0 {
        return Vec::new();
    }
    match total {
        0 => panic!("Cannot call compute_hash_from_aunts() with 0 total"),
        1 => {
            // If there is only one leaf in the tree, return its hash as a vector.
            if !inner_hashes.is_empty() {
                return Vec::new();
            }
            leaf_hash.as_bytes().to_vec()
        }
        _ => {
            if inner_hashes.is_empty() {
                return Vec::new();
            }
            let num_left = get_split_point(total);
            if index < num_left {
                // If the index is less than the split point, recursively compute the hash of the
                // left subtree using the first inner_hashes.len() - 1 inner hashes and the current
                // leaf hash.
                let left_hash = compute_hash_from_aunts(
                    index,
                    num_left,
                    leaf_hash,
                    &inner_hashes[..inner_hashes.len() - 1],
                );
                if left_hash.is_empty() {
                    return Vec::new();
                }
                // Combine the resulting hash with the last inner hash using the inner_hash function
                // to obtain the hash of the current subtree.
                inner_hash(&left_hash, inner_hashes[inner_hashes.len() - 1].as_bytes())
                    .as_bytes()
                    .to_vec()
            } else {
                // If the index is greater than or equal to the split point, recursively compute the
                // hash of the right subtree using the last inner_hashes.len() - 1 inner hashes and
                // the current leaf hash.
                let right_hash = compute_hash_from_aunts(
                    index - num_left,
                    total - num_left,
                    leaf_hash,
                    &inner_hashes[..inner_hashes.len() - 1],
                );
                if right_hash.is_empty() {
                    return Vec::new();
                }
                // Combine the resulting hash with the last inner hash using the inner_hash function
                // to obtain the hash of the current subtree.
                inner_hash(inner_hashes[inner_hashes.len() - 1].as_bytes(), &right_hash)
                    .as_bytes()
                    .to_vec()
            }
        }
    }
}

// see https://github.com/cometbft/cometbft/blob/v0.37.0/crypto/merkle/hash.go
// for the encoding of inner hash and leaf hash
fn inner_hash(left: &[u8], right: &[u8]) -> Hash {
    let mut hash_input: Vec<u8> = vec![0x01];
    hash_input.extend_from_slice(left);
    hash_input.extend_from_slice(right);
    tmhash(&hash_input)
}

fn leaf_hash(leaf: &[u8]) -> Hash {
    let mut prefixed_leaf: Vec<u8> = vec![0x00];
    prefixed_leaf.extend_from_slice(leaf);
    tmhash(&prefixed_leaf)
}

/// tmhash computes a Sha256 hash of the given data
/// Tendermint uses Sha256 as the hash function
fn tmhash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash_bytes = hasher.finalize();

    Hash::try_from(hash_bytes.to_vec()).unwrap()
}

// (ported from https://github.com/cometbft/cometbft/blob/v0.37.0/crypto/merkle/tree.go#L94-L106)
fn get_split_point(length: u64) -> u64 {
    if length < 1 {
        panic!("Trying to split a tree with size < 1");
    }
    // get number of bits required for representing `length`
    // i.e., 64 - number of MSBs with zero value in `length`
    let bit_len = 64 - length.leading_zeros();
    let k = 1_u64 << (bit_len - 1);
    if k == length {
        k >> 1
    } else {
        k
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use babylon_proto::babylon::zoneconcierge::v1::FinalizedChainInfo;
    use prost::Message;
    use std::fs;

    const TESTDATA: &str = "./testdata/finalized_chain_info.dat";

    #[test]
    fn verify_tx_in_block_works() {
        let testdata: &[u8] = &fs::read(TESTDATA).unwrap();
        let finalized_chain_info_resp = FinalizedChainInfo::decode(testdata).unwrap();
        let cz_header = &finalized_chain_info_resp
            .finalized_chain_info
            .unwrap()
            .latest_header
            .unwrap();
        let babylon_tx_hash = &cz_header.babylon_tx_hash;
        let babylon_header_data_hash = &cz_header.babylon_header.as_ref().unwrap().data_hash;
        let proof_tx_in_block = &finalized_chain_info_resp
            .proof
            .unwrap()
            .proof_tx_in_block
            .unwrap();
        verify_tx_in_block(babylon_tx_hash, babylon_header_data_hash, proof_tx_in_block).unwrap();
    }

    #[test]
    fn verify_block_in_epoch_works() {
        let testdata: &[u8] = &fs::read(TESTDATA).unwrap();
        let finalized_chain_info_resp = FinalizedChainInfo::decode(testdata).unwrap();

        let app_hash_root = &finalized_chain_info_resp.epoch_info.unwrap().app_hash_root;
        let header_app_hash = &finalized_chain_info_resp
            .finalized_chain_info
            .unwrap()
            .latest_header
            .unwrap()
            .babylon_header
            .unwrap()
            .app_hash;
        let proof_header_in_epoch = &finalized_chain_info_resp
            .proof
            .unwrap()
            .proof_header_in_epoch
            .unwrap();

        verify_block_in_epoch(header_app_hash, app_hash_root, proof_header_in_epoch).unwrap();
    }
}
