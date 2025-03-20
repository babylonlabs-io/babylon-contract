use std::str::FromStr;

use babylon_bitcoin::BlockHash;
use cosmwasm_std::Deps;

use crate::error::ContractError;
use crate::msg::btc_header::{BtcHeaderResponse, BtcHeadersResponse};
use crate::state::{get_base_header, get_header, get_header_by_hash, get_headers, get_tip};

const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

pub fn btc_base_header(deps: &Deps) -> Result<BtcHeaderResponse, ContractError> {
    let header = get_base_header(deps.storage)?;
    BtcHeaderResponse::try_from(&header)
}

pub fn btc_tip_header(deps: &Deps) -> Result<BtcHeaderResponse, ContractError> {
    let header = get_tip(deps.storage)?;
    BtcHeaderResponse::try_from(&header)
}

pub fn btc_header(deps: &Deps, height: u32) -> Result<BtcHeaderResponse, ContractError> {
    let header = get_header(deps.storage, height)?;
    BtcHeaderResponse::try_from(&header)
}

pub fn btc_header_by_hash(deps: &Deps, hash: &str) -> Result<BtcHeaderResponse, ContractError> {
    let hash = BlockHash::from_str(hash).map_err(ContractError::HashError)?;
    let header = get_header_by_hash(deps.storage, hash.as_ref())?;
    BtcHeaderResponse::try_from(&header)
}

pub fn btc_headers(
    deps: &Deps,
    start_after: Option<u32>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<BtcHeadersResponse, ContractError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let headers = get_headers(deps.storage, start_after, Some(limit), reverse)?;
    BtcHeadersResponse::try_from(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::mock_dependencies;
    use test_utils::get_btc_lc_headers;

    use crate::state::btc_light_client::init;
    use crate::state::config::{Config, CONFIG};
    use babylon_bitcoin::chain_params::Network;

    fn setup_test_state(
        deps: &mut cosmwasm_std::OwnedDeps<
            cosmwasm_std::MemoryStorage,
            cosmwasm_std::testing::MockApi,
            cosmwasm_std::testing::MockQuerier,
        >,
    ) {
        // Set config
        let cfg = Config {
            network: Network::Regtest,
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: 2,
        };
        CONFIG.save(&mut deps.storage, &cfg).unwrap();

        // Initialize with test headers
        let test_headers = get_btc_lc_headers();
        init(&mut deps.storage, &test_headers).unwrap();
    }

    #[test]
    fn test_btc_tip_header() {
        let mut deps = mock_dependencies();
        setup_test_state(&mut deps);

        let header_response = btc_tip_header(&deps.as_ref()).unwrap();
        assert!(header_response.height > 0); // Tip should be higher than base
    }

    #[test]
    fn test_btc_header() {
        let mut deps = mock_dependencies();
        setup_test_state(&mut deps);

        let header_response = btc_header(&deps.as_ref(), 1).unwrap();
        assert_eq!(header_response.height, 1);
    }
}
