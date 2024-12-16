use crate::error::CZHeaderChainError;
use crate::msg::cz_header::CzHeaderResponse;
#[cfg(feature = "btc-lc")]
use crate::state::babylon_epoch_chain::{
    get_base_epoch, get_checkpoint, get_epoch, get_last_finalized_epoch,
};
#[cfg(feature = "btc-lc")]
use crate::state::btc_light_client::{
    get_base_header, get_header, get_header_by_hash, get_headers, get_tip,
};
use crate::state::config::{Config, CONFIG};
use crate::state::cz_header_chain::{get_cz_header, get_last_cz_header};
use cosmwasm_std::{Deps, StdResult};

#[cfg(feature = "btc-lc")]
use {
    crate::error::{BTCLightclientError, BabylonEpochChainError},
    crate::msg::btc_header::BtcHeaderResponse,
    crate::msg::btc_header::BtcHeadersResponse,
    crate::msg::epoch::{CheckpointResponse, EpochResponse},
    babylon_bitcoin::BlockHash,
    std::str::FromStr,
};

pub fn config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

#[cfg(feature = "btc-lc")]
pub fn btc_base_header(deps: Deps) -> Result<BtcHeaderResponse, BTCLightclientError> {
    let btc_header_info = get_base_header(deps.storage)?;
    BtcHeaderResponse::try_from(&btc_header_info)
}

#[cfg(feature = "btc-lc")]
pub fn btc_tip_header(_deps: Deps) -> Result<BtcHeaderResponse, BTCLightclientError> {
    let btc_header_info = get_tip(_deps.storage)?;
    BtcHeaderResponse::try_from(&btc_header_info)
}

#[cfg(feature = "btc-lc")]
pub fn btc_header(deps: Deps, height: u32) -> Result<BtcHeaderResponse, BTCLightclientError> {
    let btc_header_info = get_header(deps.storage, height)?;
    BtcHeaderResponse::try_from(&btc_header_info)
}

#[cfg(feature = "btc-lc")]
pub fn btc_header_by_hash(
    deps: Deps,
    hash: &str,
) -> Result<BtcHeaderResponse, BTCLightclientError> {
    let hash = BlockHash::from_str(hash)?;
    let btc_header_info = get_header_by_hash(deps.storage, hash.as_ref())?;
    BtcHeaderResponse::try_from(&btc_header_info)
}

#[cfg(feature = "btc-lc")]
pub fn btc_headers(
    deps: Deps,
    start_after: Option<u32>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<BtcHeadersResponse, BTCLightclientError> {
    let headers = get_headers(deps.storage, start_after, limit, reverse)?;

    Ok(BtcHeadersResponse {
        headers: headers
            .iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

#[cfg(feature = "btc-lc")]
pub fn babylon_base_epoch(deps: Deps) -> Result<EpochResponse, BabylonEpochChainError> {
    let epoch = get_base_epoch(deps.storage)?;
    Ok(EpochResponse::from(&epoch))
}

#[cfg(feature = "btc-lc")]
pub fn babylon_last_epoch(deps: Deps) -> Result<EpochResponse, BabylonEpochChainError> {
    let epoch = get_last_finalized_epoch(deps.storage)?;
    Ok(EpochResponse::from(&epoch))
}

#[cfg(feature = "btc-lc")]
pub fn babylon_epoch(
    deps: Deps,
    epoch_number: u64,
) -> Result<EpochResponse, BabylonEpochChainError> {
    let epoch = get_epoch(deps.storage, epoch_number)?;
    Ok(EpochResponse::from(&epoch))
}

#[cfg(feature = "btc-lc")]
pub fn babylon_checkpoint(
    deps: Deps,
    epoch_number: u64,
) -> Result<CheckpointResponse, BabylonEpochChainError> {
    let raw_checkpoint = get_checkpoint(deps.storage, epoch_number)?;
    Ok(CheckpointResponse::from(&raw_checkpoint))
}

pub fn cz_last_header(deps: Deps) -> Result<CzHeaderResponse, CZHeaderChainError> {
    let header = get_last_cz_header(deps.storage)?;
    Ok(CzHeaderResponse::from(&header))
}

pub(crate) fn cz_header(deps: Deps, height: u64) -> Result<CzHeaderResponse, CZHeaderChainError> {
    let header = get_cz_header(deps.storage, height)?;
    Ok(CzHeaderResponse::from(&header))
}

#[cfg(all(test, feature = "btc-lc"))]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;

    use test_utils::get_btc_lc_headers;

    use crate::state::btc_light_client::{init, tests::setup};

    use super::*;

    #[test]
    fn btc_headers_work() {
        let mut deps = mock_dependencies();
        setup(deps.as_mut().storage);

        let test_headers = get_btc_lc_headers();

        init(deps.as_mut().storage, &test_headers).unwrap();

        // get headers
        let headers = btc_headers(deps.as_ref(), None, None, None)
            .unwrap()
            .headers;
        assert_eq!(headers.len(), 10); // default limit

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(header, &TryFrom::try_from(&test_headers[i]).unwrap());
        }

        // get the next 5 headers
        let headers = btc_headers(
            deps.as_ref(),
            Some(headers.last().unwrap().height),
            Some(5),
            None,
        )
        .unwrap()
        .headers;
        assert_eq!(headers.len(), 5);

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(header, &TryFrom::try_from(&test_headers[i + 10]).unwrap());
        }

        // get the next 30 headers
        let headers = btc_headers(
            deps.as_ref(),
            Some(headers.last().unwrap().height),
            Some(100),
            None,
        )
        .unwrap()
        .headers;
        assert_eq!(headers.len(), 30); // max limit

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(header, &TryFrom::try_from(&test_headers[i + 15]).unwrap());
        }

        // get the last headers
        let headers = btc_headers(deps.as_ref(), Some(90), Some(30), None)
            .unwrap()
            .headers;

        assert_eq!(headers.len(), 10); // no more headers than that
        for (i, header) in headers.iter().enumerate() {
            assert_eq!(header, &TryFrom::try_from(&test_headers[i + 90]).unwrap());
        }
    }

    #[test]
    fn btc_headers_reverse_order_work() {
        let mut deps = mock_dependencies();
        setup(deps.as_mut().storage);

        let test_headers = get_btc_lc_headers();

        init(deps.as_mut().storage, &test_headers).unwrap();

        // get headers in reverse order
        let headers = btc_headers(deps.as_ref(), None, None, Some(true))
            .unwrap()
            .headers;
        assert_eq!(headers.len(), 10); // default limit

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(
                header,
                &TryFrom::try_from(&test_headers[100 - i - 1]).unwrap()
            );
        }

        // get previous 5 headers
        let headers = btc_headers(
            deps.as_ref(),
            Some(headers.last().unwrap().height),
            Some(5),
            Some(true),
        )
        .unwrap()
        .headers;
        assert_eq!(headers.len(), 5);

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(
                header,
                &TryFrom::try_from(&test_headers[100 - 10 - i - 1]).unwrap()
            );
        }

        // get previous 30 headers
        let headers = btc_headers(
            deps.as_ref(),
            Some(headers.last().unwrap().height),
            Some(100),
            Some(true),
        )
        .unwrap()
        .headers;
        assert_eq!(headers.len(), 30); // max limit

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(
                header,
                &TryFrom::try_from(&test_headers[100 - 15 - i - 1]).unwrap()
            );
        }

        // get the first ten headers
        let headers = btc_headers(deps.as_ref(), Some(11), Some(30), Some(true))
            .unwrap()
            .headers;

        assert_eq!(headers.len(), 10); // no more headers than that
        for (i, header) in headers.iter().enumerate() {
            assert_eq!(
                header,
                &TryFrom::try_from(&test_headers[100 - 90 - i - 1]).unwrap()
            );
        }
    }
}
