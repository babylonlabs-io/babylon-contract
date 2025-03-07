//! state is the module that manages smart contract's system state
use cosmwasm_std::{DepsMut, StdError, Storage};

use crate::bindings::msg_btc_finalized_header;
use babylon_bindings::BabylonMsg;
use babylon_proto::babylon::zoneconcierge::v1::{BtcHeaders, BtcTimestamp};

pub mod babylon_epoch_chain;
pub mod config;
pub mod cz_header_chain;

/// handle_btc_timestamp handles a BTC timestamp
/// It returns an option if the BTC timestamp is verified, otherwise an error.
/// The returned option is a `FinalizedHeader` Babylon message notifying a
/// newly finalised CZ header, or None if this BTC timestamp does not carry
/// a newly finalised CZ header.
pub fn handle_btc_timestamp(
    deps: &mut DepsMut,
    btc_ts: &BtcTimestamp,
) -> Result<Option<BabylonMsg>, StdError> {
    // extract and init/handle BTC headers
    let btc_headers = btc_ts
        .btc_headers
        .as_ref()
        .ok_or_else(|| StdError::generic_err("btc_headers is None"))?;
    crate::utils::btc_light_client_executor::submit_headers(deps, &btc_headers.headers)
        .map_err(|e| StdError::generic_err(format!("failed to submit BTC headers: {e}")))?;

    // extract and init/handle Babylon epoch chain
    let (epoch, raw_ckpt, proof_epoch_sealed, txs_info) =
        babylon_epoch_chain::extract_data_from_btc_ts(btc_ts)?;
    if babylon_epoch_chain::is_initialized(&deps) {
        babylon_epoch_chain::handle_epoch_and_checkpoint(
            deps,
            epoch,
            raw_ckpt,
            proof_epoch_sealed,
            &txs_info,
        )
        .map_err(|e| {
            StdError::generic_err(format!("failed to handle Babylon epoch from Babylon: {e}"))
        })?;
    } else {
        babylon_epoch_chain::init(deps, epoch, raw_ckpt, proof_epoch_sealed, &txs_info).map_err(
            |e| StdError::generic_err(format!("failed to initialize Babylon epoch: {e}")),
        )?;
    }

    // try to extract and handle CZ header
    // it's possible that there is no CZ header checkpointed in this epoch
    if let Some(cz_header) = btc_ts.header.as_ref() {
        let proof = btc_ts
            .proof
            .as_ref()
            .ok_or(StdError::generic_err("empty proof"))?;
        let proof_cz_header_in_epoch = proof
            .proof_cz_header_in_epoch
            .as_ref()
            .ok_or(StdError::generic_err("empty proof_cz_header_in_epoch"))?;
        cz_header_chain::handle_cz_header(deps, cz_header, epoch, proof_cz_header_in_epoch)
            .map_err(|e| {
                StdError::generic_err(format!("failed to handle CZ header from Babylon: {e}"))
            })?;

        // Finalised CZ header verified, notify Cosmos zone about the newly finalised CZ header
        // Cosmos zone that deploys corresponding CosmWasm plugin will handle this message
        let msg = msg_btc_finalized_header(cz_header)?;
        return Ok(Some(msg));
    }

    Ok(None)
}

pub fn handle_btc_headers(
    deps: &mut DepsMut,
    btc_headers: &BtcHeaders,
) -> Result<Option<BabylonMsg>, StdError> {
    crate::utils::btc_light_client_executor::submit_headers(deps, &btc_headers.headers)
        .map_err(|e| StdError::generic_err(format!("failed to submit BTC headers: {e}")))?;

    Ok(None)
}
