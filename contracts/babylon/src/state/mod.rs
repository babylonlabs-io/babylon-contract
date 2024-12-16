//! state is the module that manages smart contract's system state

#[cfg(feature = "btc-lc")]
pub mod babylon_epoch_chain;
#[cfg(feature = "btc-lc")]
pub mod btc_light_client;
pub mod config;
pub mod cz_header_chain;

#[cfg(feature = "btc-lc")]
use {
    crate::bindings::msg_btc_finalized_header,
    babylon_bindings::BabylonMsg,
    babylon_proto::babylon::zoneconcierge::v1::BtcTimestamp,
    cosmwasm_std::{StdError, Storage},
};

/// handle_btc_timestamp handles a BTC timestamp
/// It returns an option if the BTC timestamp is verified, otherwise an error.
/// The returned option is a `FinalizedHeader` Babylon message notifying a
/// newly finalised CZ header, or None if this BTC timestamp does not carry
/// a newly finalised CZ header.
#[cfg(feature = "btc-lc")]
pub fn handle_btc_timestamp(
    storage: &mut dyn Storage,
    btc_ts: &BtcTimestamp,
) -> Result<Option<BabylonMsg>, StdError> {
    // extract and init/handle BTC headers
    let btc_headers = &btc_ts.btc_headers;
    if btc_light_client::is_initialized(storage) {
        btc_light_client::handle_btc_headers_from_babylon(storage, btc_headers).map_err(|e| {
            StdError::generic_err(format!("failed to handle BTC headers from Babylon: {e}"))
        })?;
    } else {
        btc_light_client::init(storage, btc_headers)
            .map_err(|e| StdError::generic_err(format!("failed to initialize BTC headers: {e}")))?;
    }

    // extract and init/handle Babylon epoch chain
    let (epoch, raw_ckpt, proof_epoch_sealed, txs_info) =
        babylon_epoch_chain::extract_data_from_btc_ts(btc_ts)?;
    if babylon_epoch_chain::is_initialized(storage) {
        babylon_epoch_chain::handle_epoch_and_checkpoint(
            storage,
            epoch,
            raw_ckpt,
            proof_epoch_sealed,
            &txs_info,
        )
        .map_err(|e| {
            StdError::generic_err(format!("failed to handle Babylon epoch from Babylon: {e}"))
        })?;
    } else {
        babylon_epoch_chain::init(storage, epoch, raw_ckpt, proof_epoch_sealed, &txs_info)
            .map_err(|e| {
                StdError::generic_err(format!("failed to initialize Babylon epoch: {e}"))
            })?;
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
        cz_header_chain::handle_cz_header(storage, cz_header, epoch, proof_cz_header_in_epoch)
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
