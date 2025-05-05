use crate::error;
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::IndexedHeader;
use prost::Message;
use tendermint_proto::crypto::ProofOps;

/// verify_tx_in_block verifies whether a tx with tx_hash is committed to
/// the Merkle root hash of a Tendermint block
pub fn verify_consumer_header_in_epoch(
    cz_header: &IndexedHeader,
    epoch: &Epoch,
    proof_cz_header_in_epoch: &ProofOps,
) -> Result<(), error::ConsumerHeaderChainError> {
    // verify CZ header has correct epoch number
    if cz_header.babylon_epoch != epoch.epoch_number {
        return Err(error::ConsumerHeaderChainError::EpochNumberError {});
    }

    // Ensure the CZ header is committed to the app_hash of the sealer header
    let root = &epoch.sealer_app_hash;
    let cz_header_key =
        super::cosmos_store::get_cz_header_key(&cz_header.consumer_id, cz_header.height);
    let cz_header_bytes = cz_header.encode_to_vec();
    super::cosmos_store::verify_store(
        root,
        super::cosmos_store::ZONECONCIERGE_STORE_KEY,
        &cz_header_key,
        &cz_header_bytes,
        proof_cz_header_in_epoch,
    )
    .map_err(|_| error::ConsumerHeaderChainError::ProofError {})?;

    Ok(())
}

// TODO: test
