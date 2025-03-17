//! cz_header_chain is the storage for the chain of **finalised** CZ headers.
//! It maintains a chain of finalised CZ headers.
//! NOTE: the CZ header chain is always finalised, i.e., w-deep on BTC.
use prost::Message;
use tendermint_proto::crypto::ProofOps;

use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::{Item, Map};

use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::IndexedHeader;

use crate::state::config::CONFIG;
use crate::{error, utils};

pub const CZ_HEADERS: Map<u64, Vec<u8>> = Map::new("cz_headers");
pub const CZ_HEADER_LAST: Item<Vec<u8>> = Item::new("cz_header_last");
pub const CZ_HEIGHT_LAST: Item<u64> = Item::new("cz_height_last");

// getter/setter for last finalised CZ header
pub fn get_last_cz_header(
    storage: &dyn Storage,
) -> Result<IndexedHeader, error::CZHeaderChainError> {
    let last_cz_header_bytes = CZ_HEADER_LAST
        .load(storage)
        .map_err(|_| error::CZHeaderChainError::NoCZHeader {})?;
    IndexedHeader::decode(last_cz_header_bytes.as_slice())
        .map_err(error::CZHeaderChainError::DecodeError)
}

// Getter/setter for last finalised CZ height
// Zero means no finalised CZ header yet
pub fn get_last_cz_height(storage: &dyn Storage) -> StdResult<u64> {
    CZ_HEIGHT_LAST.load(storage)
}

fn set_last_cz_header(storage: &mut dyn Storage, last_cz_header: &IndexedHeader) -> StdResult<()> {
    let last_cz_header_bytes = &last_cz_header.encode_to_vec();
    CZ_HEADER_LAST
        .save(storage, last_cz_header_bytes)
        // Save the height of the last finalised CZ header in passing as well
        .and(CZ_HEIGHT_LAST.save(storage, &last_cz_header.height))
}

/// get_cz_header gets a CZ header of a given height
pub fn get_cz_header(
    storage: &dyn Storage,
    height: u64,
) -> Result<IndexedHeader, error::CZHeaderChainError> {
    // try to find the indexed header at the given height
    let cz_header_bytes = CZ_HEADERS
        .load(storage, height)
        .map_err(|_| error::CZHeaderChainError::CZHeaderNotFoundError { height })?;

    // try to decode the indexed_header
    let indexed_header = IndexedHeader::decode(cz_header_bytes.as_slice())?;

    Ok(indexed_header)
}

/// verify_cz_header verifies whether a CZ header is committed to a Babylon epoch, including
/// - The Babylon tx carrying this header is included in a Babylon block
/// - The Babylon block's AppHash is committed to the AppHashRoot of the epoch
fn verify_cz_header(
    storage: &mut dyn Storage,
    cz_header: &IndexedHeader,
    epoch: &Epoch,
    proof_cz_header_in_epoch: &ProofOps,
) -> Result<(), error::CZHeaderChainError> {
    let _cfg = CONFIG.load(storage)?;

    // check if the corresponding CZ header is in the Babylon epoch
    utils::cz_header_chain::verify_cz_header_in_epoch(cz_header, epoch, proof_cz_header_in_epoch)?;

    // TODO: check if IndexedHeader is conflicted or not. Still not sure if this check should happen
    // in a relayer/monitor or the smart contract, given that smart contract has no access to the
    // Tendermint ledger

    Ok(())
}

fn insert_cz_header(storage: &mut dyn Storage, cz_header: &IndexedHeader) -> StdResult<()> {
    // insert indexed header
    let cz_header_bytes = cz_header.encode_to_vec();
    CZ_HEADERS.save(storage, cz_header.height, &cz_header_bytes)?;

    // update last finalised header
    set_last_cz_header(storage, cz_header)
}

// TODO: unit test
pub fn handle_cz_header(
    storage: &mut dyn Storage,
    cz_header: &IndexedHeader,
    epoch: &Epoch,
    proof_cz_header_in_epoch: &ProofOps,
) -> Result<(), error::CZHeaderChainError> {
    verify_cz_header(storage, cz_header, epoch, proof_cz_header_in_epoch)?;
    insert_cz_header(storage, cz_header)?;

    Ok(())
}
