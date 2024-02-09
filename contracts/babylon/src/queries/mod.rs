use crate::error::{BTCLightclientError, BabylonEpochChainError, CZHeaderChainError};
use crate::msg::btc_header::BtcHeaderResponse;
use crate::msg::cz_header::CzHeaderResponse;
use crate::msg::epoch::{CheckpointResponse, EpochResponse};
use crate::state::babylon_epoch_chain::{
    get_base_epoch, get_checkpoint, get_epoch, get_last_finalized_epoch,
};
use crate::state::btc_light_client::{get_base_header, get_header, get_header_by_hash, get_tip};
use crate::state::config::{Config, CONFIG};
use crate::state::cz_header_chain::{get_cz_header, get_last_cz_header};
use babylon_bitcoin::BlockHash;
use cosmwasm_std::{Deps, StdResult};
use std::str::FromStr;

pub fn config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn btc_base_header(deps: Deps) -> Result<BtcHeaderResponse, BTCLightclientError> {
    let btc_header_info = get_base_header(deps.storage)?;
    BtcHeaderResponse::try_from(&btc_header_info)
}

pub fn btc_tip_header(_deps: Deps) -> Result<BtcHeaderResponse, BTCLightclientError> {
    let btc_header_info = get_tip(_deps.storage)?;
    BtcHeaderResponse::try_from(&btc_header_info)
}

pub fn btc_header(deps: Deps, height: u64) -> Result<BtcHeaderResponse, BTCLightclientError> {
    let btc_header_info = get_header(deps.storage, height)?;
    BtcHeaderResponse::try_from(&btc_header_info)
}

pub fn btc_header_by_hash(
    deps: Deps,
    hash: &str,
) -> Result<BtcHeaderResponse, BTCLightclientError> {
    let hash = BlockHash::from_str(hash)?;
    let btc_header_info = get_header_by_hash(deps.storage, hash.as_ref())?;
    BtcHeaderResponse::try_from(&btc_header_info)
}

pub fn babylon_base_epoch(deps: Deps) -> Result<EpochResponse, BabylonEpochChainError> {
    let epoch = get_base_epoch(deps.storage)?;
    Ok(EpochResponse::from(&epoch))
}

pub fn babylon_last_epoch(deps: Deps) -> Result<EpochResponse, BabylonEpochChainError> {
    let epoch = get_last_finalized_epoch(deps.storage)?;
    Ok(EpochResponse::from(&epoch))
}

pub fn babylon_epoch(
    deps: Deps,
    epoch_number: u64,
) -> Result<EpochResponse, BabylonEpochChainError> {
    let epoch = get_epoch(deps.storage, epoch_number)?;
    Ok(EpochResponse::from(&epoch))
}

pub fn babylon_checkpoint(
    deps: Deps,
    epoch_number: u64,
) -> Result<CheckpointResponse, BabylonEpochChainError> {
    let raw_checkpoint = get_checkpoint(deps.storage, epoch_number)?;
    Ok(CheckpointResponse::from(&raw_checkpoint))
}

pub fn cz_last_header(deps: Deps) -> Result<CzHeaderResponse, CZHeaderChainError> {
    let header = get_last_cz_header(deps.storage)?;
    CzHeaderResponse::try_from(&header)
}

pub(crate) fn cz_header(deps: Deps, height: u64) -> Result<CzHeaderResponse, CZHeaderChainError> {
    let header = get_cz_header(deps.storage, height)?;
    CzHeaderResponse::try_from(&header)
}
