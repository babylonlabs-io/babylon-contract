#[derive(Debug)]
pub enum CommitmentError {
    /// failed to decode commitment proof error: `{0}`
    CommitmentProofDecodingFailed,
    /// empty merkle proof
    EmptyMerkleProof,
    /// empty merkle root
    EmptyMerkleRoot,
    /// empty verified value
    EmptyVerifiedValue,
    /// mismatch between the number of proofs with that of specs
    NumberOfSpecsMismatch,
    /// mismatch between the number of proofs with that of keys
    NumberOfKeysMismatch,
    /// invalid merkle proof
    InvalidMerkleProof,
    /// proof verification failed
    VerificationFailure,
}
