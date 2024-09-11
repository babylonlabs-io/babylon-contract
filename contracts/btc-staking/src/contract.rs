#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Deps, DepsMut, Empty, Env, MessageInfo, QueryResponse, Reply, Response,
    StdResult,
};
use cw2::set_contract_version;
use cw_utils::{maybe_addr, nonpayable};

use babylon_apis::btc_staking_api::SudoMsg;
use babylon_bindings::BabylonMsg;

use crate::error::ContractError;
use crate::finality::{
    compute_active_finality_providers, handle_finality_signature, handle_public_randomness_commit,
};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::staking::handle_btc_staking;
use crate::state::config::{Config, ADMIN, CONFIG, PARAMS};
use crate::state::staking::ACTIVATED_HEIGHT;
use crate::{finality, queries, state};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    mut deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    nonpayable(&info)?;
    let denom = deps.querier.query_bonded_denom()?;
    let config = Config {
        denom,
        babylon: info.sender,
    };
    CONFIG.save(deps.storage, &config)?;

    let api = deps.api;
    ADMIN.set(deps.branch(), maybe_addr(api, msg.admin.clone())?)?;

    let params = msg.params.unwrap_or_default();
    PARAMS.save(deps.storage, &params)?;
    // initialize storage, so no issue when reading for the first time

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_deps: DepsMut, _env: Env, _reply: Reply) -> StdResult<Response> {
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<QueryResponse, ContractError> {
    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&queries::config(deps)?)?),
        QueryMsg::Params {} => Ok(to_json_binary(&queries::params(deps)?)?),
        QueryMsg::Admin {} => to_json_binary(&ADMIN.query_admin(deps)?).map_err(Into::into),
        QueryMsg::FinalityProvider { btc_pk_hex } => Ok(to_json_binary(
            &queries::finality_provider(deps, btc_pk_hex)?,
        )?),
        QueryMsg::FinalityProviders { start_after, limit } => Ok(to_json_binary(
            &queries::finality_providers(deps, start_after, limit)?,
        )?),
        QueryMsg::Delegation {
            staking_tx_hash_hex,
        } => Ok(to_json_binary(&queries::delegation(
            deps,
            staking_tx_hash_hex,
        )?)?),
        QueryMsg::Delegations {
            start_after,
            limit,
            active,
        } => Ok(to_json_binary(&queries::delegations(
            deps,
            start_after,
            limit,
            active,
        )?)?),
        QueryMsg::DelegationsByFP { btc_pk_hex } => Ok(to_json_binary(
            &queries::delegations_by_fp(deps, btc_pk_hex)?,
        )?),
        QueryMsg::FinalityProviderInfo { btc_pk_hex, height } => Ok(to_json_binary(
            &queries::finality_provider_info(deps, btc_pk_hex, height)?,
        )?),
        QueryMsg::FinalityProvidersByPower { start_after, limit } => Ok(to_json_binary(
            &queries::finality_providers_by_power(deps, start_after, limit)?,
        )?),
        QueryMsg::FinalitySignature { btc_pk_hex, height } => Ok(to_json_binary(
            &queries::finality_signature(deps, btc_pk_hex, height)?,
        )?),
        QueryMsg::PubRandCommit {
            btc_pk_hex,
            start_after,
            limit,
            reverse,
        } => Ok(to_json_binary(
            &state::public_randomness::get_pub_rand_commit(
                deps.storage,
                &btc_pk_hex,
                start_after,
                limit,
                reverse,
            )?,
        )?),
        QueryMsg::FirstPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &state::public_randomness::get_first_pub_rand_commit(deps.storage, &btc_pk_hex)?,
        )?),
        QueryMsg::LastPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &state::public_randomness::get_last_pub_rand_commit(deps.storage, &btc_pk_hex)?,
        )?),
        QueryMsg::ActivatedHeight {} => Ok(to_json_binary(&queries::activated_height(deps)?)?),
        QueryMsg::Block { height } => Ok(to_json_binary(&queries::block(deps, height)?)?),
        QueryMsg::Blocks {
            start_after,
            limit,
            finalised,
            reverse,
        } => Ok(to_json_binary(&queries::blocks(
            deps,
            start_after,
            limit,
            finalised,
            reverse,
        )?)?),
        QueryMsg::Evidence { btc_pk_hex, height } => Ok(to_json_binary(&queries::evidence(
            deps, btc_pk_hex, height,
        )?)?),
    }
}

/// This is a no-op just to test how this integrates with wasmd
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: Empty) -> StdResult<Response> {
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    let api = deps.api;
    match msg {
        ExecuteMsg::UpdateAdmin { admin } => ADMIN
            .execute_update_admin(deps, info, maybe_addr(api, admin)?)
            .map_err(Into::into),
        ExecuteMsg::BtcStaking {
            new_fp,
            active_del,
            slashed_del,
            unbonded_del,
        } => handle_btc_staking(
            deps,
            env,
            &info,
            &new_fp,
            &active_del,
            &slashed_del,
            &unbonded_del,
        ),
        ExecuteMsg::SubmitFinalitySignature {
            fp_pubkey_hex,
            height,
            pub_rand,
            proof,
            block_hash,
            signature,
        } => handle_finality_signature(
            deps,
            env,
            &fp_pubkey_hex,
            height,
            &pub_rand,
            &proof,
            &block_hash,
            &signature,
        ),
        ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex,
            start_height,
            num_pub_rand,
            commitment,
            signature,
        } => handle_public_randomness_commit(
            deps,
            &fp_pubkey_hex,
            start_height,
            num_pub_rand,
            &commitment,
            &signature,
        ),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(
    mut deps: DepsMut,
    env: Env,
    msg: SudoMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    match msg {
        SudoMsg::BeginBlock { .. } => handle_begin_block(&mut deps, env),
        SudoMsg::EndBlock {
            hash_hex,
            app_hash_hex,
        } => handle_end_block(&mut deps, env, &hash_hex, &app_hash_hex),
    }
}

fn handle_begin_block(deps: &mut DepsMut, env: Env) -> Result<Response<BabylonMsg>, ContractError> {
    // Compute active finality provider set
    let max_active_fps = PARAMS.load(deps.storage)?.max_active_finality_providers as usize;
    compute_active_finality_providers(deps.storage, env, max_active_fps)?;

    Ok(Response::new())
}

fn handle_end_block(
    deps: &mut DepsMut,
    env: Env,
    _hash_hex: &str,
    app_hash_hex: &str,
) -> Result<Response<BabylonMsg>, ContractError> {
    // If the BTC staking protocol is activated i.e. there exists a height where at least one
    // finality provider has voting power, start indexing and tallying blocks
    let mut res = Response::new();
    if let Some(activated_height) = ACTIVATED_HEIGHT.may_load(deps.storage)? {
        // Index the current block
        let ev = finality::index_block(deps, env.block.height, &hex::decode(app_hash_hex)?)?;
        res = res.add_event(ev);
        // Tally all non-finalised blocks
        let events = finality::tally_blocks(deps, activated_height, env.block.height)?;
        res = res.add_events(events);
    }
    Ok(res)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::str::FromStr;

    use super::*;

    use crate::state::config::Params;
    use babylon_apis::btc_staking_api::{
        ActiveBtcDelegation, BtcUndelegationInfo, CovenantAdaptorSignatures,
        FinalityProviderDescription, NewFinalityProvider, ProofOfPossessionBtc,
    };
    use babylon_apis::finality_api::PubRandCommit;
    use babylon_bitcoin::chain_params::Network;
    use babylon_proto::babylon::btcstaking::v1::{
        BtcDelegation, FinalityProvider, Params as ProtoParams,
    };
    use cosmwasm_std::{
        from_json,
        testing::{message_info, mock_dependencies, mock_env},
        Binary, Decimal,
    };
    use cw_controllers::AdminResponse;
    use hex::ToHex;
    use k256::schnorr::{Signature, SigningKey};
    use test_utils::{
        get_btc_del_unbonding_sig_bytes, get_btc_delegation, get_finality_provider,
        get_fp_sk_bytes, get_pub_rand_commit,
    };

    pub(crate) const CREATOR: &str = "creator";
    pub(crate) const INIT_ADMIN: &str = "initial_admin";
    const NEW_ADMIN: &str = "new_admin";

    fn new_params(params: ProtoParams) -> Params {
        Params {
            covenant_pks: params.covenant_pks.iter().map(hex::encode).collect(),
            covenant_quorum: params.covenant_quorum,
            btc_network: Network::Regtest, // TODO: fix this
            max_active_finality_providers: params.max_active_finality_providers,
            min_pub_rand: 10, // TODO: fix this
            slashing_address: params.slashing_address,
            min_slashing_tx_fee_sat: params.min_slashing_tx_fee_sat as u64,
            slashing_rate: "0.01".to_string(), // TODO: fix this
        }
    }

    pub(crate) fn get_params() -> Params {
        let proto_params = test_utils::get_params();
        new_params(proto_params)
    }

    fn new_finality_provider(fp: FinalityProvider) -> NewFinalityProvider {
        NewFinalityProvider {
            addr: fp.addr,
            description: fp.description.map(|desc| FinalityProviderDescription {
                moniker: desc.moniker,
                identity: desc.identity,
                website: desc.website,
                security_contact: desc.security_contact,
                details: desc.details,
            }),
            commission: Decimal::from_str(&fp.commission).unwrap(),
            btc_pk_hex: fp.btc_pk.encode_hex(),
            pop: match fp.pop {
                Some(pop) => Some(ProofOfPossessionBtc {
                    btc_sig_type: pop.btc_sig_type,
                    btc_sig: Binary::new(pop.btc_sig.to_vec()),
                }),
                None => None,
            },
            consumer_id: fp.consumer_id,
        }
    }

    fn new_active_btc_delegation(del: BtcDelegation) -> ActiveBtcDelegation {
        let btc_undelegation = del.btc_undelegation.unwrap();

        ActiveBtcDelegation {
            staker_addr: del.staker_addr,
            btc_pk_hex: del.btc_pk.encode_hex(),
            fp_btc_pk_list: del
                .fp_btc_pk_list
                .iter()
                .map(|fp_btc_pk| fp_btc_pk.encode_hex())
                .collect(),
            start_height: del.start_height,
            end_height: del.end_height,
            total_sat: del.total_sat,
            staking_tx: Binary::new(del.staking_tx.to_vec()),
            slashing_tx: Binary::new(del.slashing_tx.to_vec()),
            delegator_slashing_sig: Binary::new(del.delegator_sig.to_vec()),
            covenant_sigs: del
                .covenant_sigs
                .iter()
                .map(|cov_sig| CovenantAdaptorSignatures {
                    cov_pk: Binary::new(cov_sig.cov_pk.to_vec()),
                    adaptor_sigs: cov_sig
                        .adaptor_sigs
                        .iter()
                        .map(|adaptor_sig| Binary::new(adaptor_sig.to_vec()))
                        .collect(),
                })
                .collect(),
            staking_output_idx: del.staking_output_idx,
            unbonding_time: del.unbonding_time,
            undelegation_info: BtcUndelegationInfo {
                unbonding_tx: Binary::new(btc_undelegation.unbonding_tx.to_vec()),
                slashing_tx: Binary::new(btc_undelegation.slashing_tx.to_vec()),
                delegator_unbonding_sig: Binary::new(
                    btc_undelegation.delegator_unbonding_sig.to_vec(),
                ),
                delegator_slashing_sig: Binary::new(
                    btc_undelegation.delegator_slashing_sig.to_vec(),
                ),
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            },
            params_version: del.params_version,
        }
    }

    /// Build an active BTC delegation from a BTC delegation
    pub(crate) fn get_active_btc_delegation() -> ActiveBtcDelegation {
        let del = get_btc_delegation(1, vec![1]);
        new_active_btc_delegation(del)
    }

    // Build a derived active BTC delegation from the base (from testdata) BTC delegation
    pub(crate) fn get_derived_btc_delegation(del_id: i32, fp_ids: &[i32]) -> ActiveBtcDelegation {
        let del = get_btc_delegation(del_id, fp_ids.to_vec());
        new_active_btc_delegation(del)
    }

    pub(crate) fn get_btc_del_unbonding_sig(del_id: i32, fp_ids: &[i32]) -> Signature {
        let sig_bytes = get_btc_del_unbonding_sig_bytes(del_id, fp_ids.to_vec());
        Signature::try_from(sig_bytes.as_slice()).unwrap()
    }

    /// Get public randomness public key, commitment, and signature information
    ///
    /// Signature is a Schnorr signature over the commitment
    pub(crate) fn get_public_randomness_commitment() -> (String, PubRandCommit, Vec<u8>) {
        let pub_rand_commitment_msg = get_pub_rand_commit();
        (
            pub_rand_commitment_msg.fp_btc_pk.encode_hex(),
            PubRandCommit {
                start_height: pub_rand_commitment_msg.start_height,
                num_pub_rand: pub_rand_commitment_msg.num_pub_rand,
                commitment: pub_rand_commitment_msg.commitment.to_vec(),
            },
            pub_rand_commitment_msg.sig.to_vec(),
        )
    }

    pub(crate) fn create_new_finality_provider(id: i32) -> NewFinalityProvider {
        let fp = get_finality_provider(id);
        new_finality_provider(fp)
    }

    pub(crate) fn create_new_fp_sk(id: i32) -> SigningKey {
        let fp_sk_bytes = get_fp_sk_bytes(id);
        SigningKey::from_bytes(&fp_sk_bytes).unwrap()
    }

    #[test]
    fn instantiate_without_admin() {
        let mut deps = mock_dependencies();

        // Create an InstantiateMsg with admin set to None
        let msg = InstantiateMsg {
            params: None,
            admin: None, // No admin provided
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Query the admin to verify it was not set
        let res = ADMIN.query_admin(deps.as_ref()).unwrap();
        assert_eq!(None, res.admin);
    }

    #[test]
    fn instantiate_with_admin() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let msg = InstantiateMsg {
            params: None,
            admin: Some(init_admin.to_string()), // Admin provided
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was set correctly
        // This uses the assert_admin helper function provided by the Admin crate
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // ensure the admin is queryable as well
        let res = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
        let admin: AdminResponse = from_json(res).unwrap();
        assert_eq!(admin.admin.unwrap(), init_admin.as_str())
    }

    #[test]
    fn test_update_admin() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);

        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let instantiate_msg = InstantiateMsg {
            params: None,
            admin: Some(init_admin.to_string()), // Admin provided
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was set correctly
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // Update the admin to new_admin
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: Some(new_admin.to_string()),
        };

        // Execute the UpdateAdmin message with non-admin info
        let non_admin_info = message_info(&deps.api.addr_make("non_admin"), &[]);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            non_admin_info,
            update_admin_msg.clone(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ContractError::Admin(cw_controllers::AdminError::NotAdmin {})
        );

        // Execute the UpdateAdmin message with the initial admin info
        let admin_info = message_info(&init_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was updated correctly
        ADMIN.assert_admin(deps.as_ref(), &new_admin).unwrap();
    }
}
