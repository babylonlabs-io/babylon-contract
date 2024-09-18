use cosmwasm_schema::cw_serde;
use cw_storage_plus::{IndexedSnapshotMap, Item, Map, MultiIndex, Strategy};

use crate::state::fp_index::FinalityProviderIndexes;
use babylon_apis::btc_staking_api::{BTCDelegationStatus, FinalityProvider, HASH_SIZE};
use babylon_apis::{btc_staking_api, Bytes};

#[cw_serde]
pub struct BtcDelegation {
    /// staker_addr is the address to receive rewards from BTC delegation
    pub staker_addr: String,
    /// btc_pk_hex is the Bitcoin secp256k1 PK of the BTC delegator.
    /// The PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// fp_btc_pk_list is the list of BIP-340 PKs of the finality providers that
    /// this BTC delegation delegates to
    pub fp_btc_pk_list: Vec<String>,
    /// start_height is the start BTC height of the BTC delegation.
    /// It is the start BTC height of the time-lock
    pub start_height: u64,
    /// end_height is the end height of the BTC delegation
    /// it is the end BTC height of the time-lock - w
    pub end_height: u64,
    /// total_sat is the total BTC stakes in this delegation, quantified in satoshi
    pub total_sat: u64,
    /// staking_tx is the staking tx
    pub staking_tx: Bytes,
    /// slashing_tx is the slashing tx
    pub slashing_tx: Bytes,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e. SK corresponding to btc_pk) as string hex.
    /// It will be a part of the witness for the staking tx output.
    pub delegator_slashing_sig: Bytes,
    /// covenant_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member.
    /// It will be a part of the witness for the staking tx output.
    pub covenant_sigs: Vec<CovenantAdaptorSignatures>,
    /// staking_output_idx is the index of the staking output in the staking tx
    pub staking_output_idx: u32,
    /// unbonding_time is used in unbonding output time-lock path and in slashing transactions
    /// change outputs
    pub unbonding_time: u32,
    /// undelegation_info is the undelegation info of this delegation.
    pub undelegation_info: BtcUndelegationInfo,
    /// params version used to validate the delegation
    pub params_version: u32,
    /// slashed is used to indicate whether a given delegation is related to a slashed FP
    pub slashed: bool,
}

impl BtcDelegation {
    pub fn is_active(&self) -> bool {
        // TODO: Implement full delegation status checks (needs BTC height)
        // self.get_status(btc_height, w) == BTCDelegationStatus::ACTIVE
        !self.is_unbonded_early() && !self.is_slashed()
    }

    fn is_unbonded_early(&self) -> bool {
        !self.undelegation_info.delegator_unbonding_sig.is_empty()
    }

    fn is_slashed(&self) -> bool {
        self.slashed
    }

    pub fn get_status(&self, btc_height: u64, w: u64) -> BTCDelegationStatus {
        // Manually unbonded, staking tx time-lock has not begun, is less than w BTC blocks left, or
        // has expired
        if self.is_unbonded_early()
            || btc_height < self.start_height
            || btc_height + w > self.end_height
            || self.is_slashed()
        {
            BTCDelegationStatus::UNBONDED
        } else {
            // At this point, the BTC delegation has an active time-lock, and Babylon is not aware of
            // an unbonding tx with the delegator's signature
            BTCDelegationStatus::ACTIVE
        }
    }
}

impl From<btc_staking_api::ActiveBtcDelegation> for BtcDelegation {
    fn from(active_delegation: btc_staking_api::ActiveBtcDelegation) -> Self {
        BtcDelegation {
            staker_addr: active_delegation.staker_addr,
            btc_pk_hex: active_delegation.btc_pk_hex,
            fp_btc_pk_list: active_delegation.fp_btc_pk_list,
            start_height: active_delegation.start_height,
            end_height: active_delegation.end_height,
            total_sat: active_delegation.total_sat,
            staking_tx: active_delegation.staking_tx.to_vec(),
            slashing_tx: active_delegation.slashing_tx.to_vec(),
            delegator_slashing_sig: active_delegation.delegator_slashing_sig.to_vec(),
            covenant_sigs: active_delegation
                .covenant_sigs
                .into_iter()
                .map(|sig| sig.into())
                .collect(),
            staking_output_idx: active_delegation.staking_output_idx,
            unbonding_time: active_delegation.unbonding_time,
            undelegation_info: active_delegation.undelegation_info.into(),
            params_version: active_delegation.params_version,
            slashed: false,
        }
    }
}

impl From<&btc_staking_api::ActiveBtcDelegation> for BtcDelegation {
    fn from(active_delegation: &btc_staking_api::ActiveBtcDelegation) -> Self {
        BtcDelegation::from(active_delegation.clone())
    }
}

#[cw_serde]
pub struct CovenantAdaptorSignatures {
    /// cov_pk is the public key of the covenant emulator, used as the public key of the adaptor signature
    pub cov_pk: Bytes,
    /// adaptor_sigs is a list of adaptor signatures, each encrypted by a restaked BTC finality provider's public key
    pub adaptor_sigs: Vec<Bytes>,
}

impl From<btc_staking_api::CovenantAdaptorSignatures> for CovenantAdaptorSignatures {
    fn from(cov_adaptor_sigs: btc_staking_api::CovenantAdaptorSignatures) -> Self {
        CovenantAdaptorSignatures {
            cov_pk: cov_adaptor_sigs.cov_pk.to_vec(),
            adaptor_sigs: cov_adaptor_sigs
                .adaptor_sigs
                .into_iter()
                .map(|sig| sig.to_vec())
                .collect(),
        }
    }
}

#[cw_serde]
pub struct BtcUndelegationInfo {
    /// unbonding_tx is the transaction which will transfer the funds from staking
    /// output to unbonding output. Unbonding output will usually have lower timelock
    /// than staking output.
    pub unbonding_tx: Bytes,
    /// delegator_unbonding_sig is the signature on the unbonding tx
    /// by the delegator (i.e. SK corresponding to btc_pk).
    /// It effectively proves that the delegator wants to unbond and thus
    /// Babylon will consider this BTC delegation unbonded. Delegator's BTC
    /// on Bitcoin will be unbonded after time-lock.
    pub delegator_unbonding_sig: Bytes,
    /// covenant_unbonding_sig_list is the list of signatures on the unbonding tx
    /// by covenant members
    pub covenant_unbonding_sig_list: Vec<SignatureInfo>,
    /// slashing_tx is the unbonding slashing tx
    pub slashing_tx: Bytes,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e. SK corresponding to btc_pk).
    /// It will be a part of the witness for the unbonding tx output.
    pub delegator_slashing_sig: Bytes,
    /// covenant_slashing_sigs is a list of adaptor signatures on the
    /// unbonding slashing tx by each covenant member
    /// It will be a part of the witness for the staking tx output.
    pub covenant_slashing_sigs: Vec<CovenantAdaptorSignatures>,
}

impl From<btc_staking_api::BtcUndelegationInfo> for BtcUndelegationInfo {
    fn from(undelegation_info: btc_staking_api::BtcUndelegationInfo) -> Self {
        BtcUndelegationInfo {
            unbonding_tx: undelegation_info.unbonding_tx.to_vec(),
            delegator_unbonding_sig: undelegation_info.delegator_unbonding_sig.to_vec(),
            covenant_unbonding_sig_list: undelegation_info
                .covenant_unbonding_sig_list
                .into_iter()
                .map(|sig| sig.into())
                .collect(),
            slashing_tx: undelegation_info.slashing_tx.to_vec(),
            delegator_slashing_sig: undelegation_info.delegator_slashing_sig.to_vec(),
            covenant_slashing_sigs: undelegation_info
                .covenant_slashing_sigs
                .into_iter()
                .map(|sig| sig.into())
                .collect(),
        }
    }
}

#[cw_serde]
pub struct SignatureInfo {
    pub pk: Bytes,
    pub sig: Bytes,
}

impl From<btc_staking_api::SignatureInfo> for SignatureInfo {
    fn from(sig_info: btc_staking_api::SignatureInfo) -> Self {
        SignatureInfo {
            pk: sig_info.pk.to_vec(),
            sig: sig_info.sig.to_vec(),
        }
    }
}

/// Finality providers by their BTC public key
pub(crate) const FPS: Map<&str, FinalityProvider> = Map::new("fps");

/// Delegations by staking tx hash
/// TODO: create a new DB object for BTC delegation
pub(crate) const DELEGATIONS: Map<&[u8; HASH_SIZE], BtcDelegation> = Map::new("delegations");
/// Map of staking hashes by finality provider
pub(crate) const FP_DELEGATIONS: Map<&str, Vec<Vec<u8>>> = Map::new("fp_delegations");
/// Reverse map of finality providers by staking hash
pub(crate) const DELEGATION_FPS: Map<&[u8; HASH_SIZE], Vec<String>> = Map::new("delegation_fps");

pub const FP_STATE_KEY: &str = "fp_state";
const FP_STATE_CHECKPOINTS: &str = "fp_state__checkpoints";
const FP_STATE_CHANGELOG: &str = "fp_state__changelog";
pub const FP_POWER_KEY: &str = "fp_state__power";

/// The height at which the contract gets its first delegation
pub const ACTIVATED_HEIGHT: Item<u64> = Item::new("activated_height");

/// Indexed snapshot map for finality providers.
///
/// This allows querying the map finality providers, sorted by their (aggregated) power.
/// The power index is a `MultiIndex`, as there can be multiple FPs with the same power.
///
/// The indexes are not snapshotted; only the current power is indexed at any given time.
pub fn fps<'a>() -> IndexedSnapshotMap<&'a str, FinalityProviderState, FinalityProviderIndexes<'a>>
{
    let indexes = FinalityProviderIndexes {
        power: MultiIndex::new(|_, fp_state| fp_state.power, FP_STATE_KEY, FP_POWER_KEY),
    };
    IndexedSnapshotMap::new(
        FP_STATE_KEY,
        FP_STATE_CHECKPOINTS,
        FP_STATE_CHANGELOG,
        Strategy::EveryBlock,
        indexes,
    )
}

#[cw_serde]
#[derive(Default)]
pub struct FinalityProviderState {
    /// Finality provider power, in satoshis
    pub power: u64,
}
