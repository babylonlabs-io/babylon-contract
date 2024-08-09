use cosmwasm_schema::cw_serde;
use cw_storage_plus::{IndexedSnapshotMap, Item, Map, MultiIndex, Strategy};

use crate::error::ContractError;
use crate::msg::FinalityProviderInfo;
use crate::state::fp_index::FinalityProviderIndexes;
use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, BTCDelegationStatus, BtcUndelegationInfo, CovenantAdaptorSignatures,
    FinalityProvider, SignatureInfo, HASH_SIZE,
};
use babylon_apis::Bytes;

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
    pub undelegation_info: UndelegationInfo,
    /// params version used to validate the delegation
    pub params_version: u32,
}

impl BtcDelegation {
    pub fn is_active(&self) -> bool {
        // TODO: Implement full delegation status checks (needs BTC height)
        // self.get_status(btc_height, w) == BTCDelegationStatus::ACTIVE
        !self.is_unbonded_early()
    }

    fn is_unbonded_early(&self) -> bool {
        !self.undelegation_info.delegator_unbonding_sig.is_empty()
    }

    pub fn get_status(&self, btc_height: u64, w: u64) -> BTCDelegationStatus {
        // Manually unbonded, staking tx time-lock has not begun, is less than w BTC blocks left, or
        // has expired
        if self.is_unbonded_early()
            || btc_height < self.start_height
            || btc_height + w > self.end_height
        {
            BTCDelegationStatus::UNBONDED
        } else {
            // At this point, the BTC delegation has an active time-lock, and Babylon is not aware of
            // an unbonding tx with the delegator's signature
            BTCDelegationStatus::ACTIVE
        }
    }
}

impl TryFrom<ActiveBtcDelegation> for BtcDelegation {
    type Error = ContractError;

    fn try_from(delegation: ActiveBtcDelegation) -> Result<Self, Self::Error> {
        let btc_undelegation_info = match delegation.undelegation_info {
            Some(info) => info,
            None => return Err(ContractError::MissingUnbondingInfo {}),
        };
        Ok(BtcDelegation {
            staker_addr: delegation.staker_addr,
            btc_pk_hex: delegation.btc_pk_hex,
            fp_btc_pk_list: delegation.fp_btc_pk_list,
            start_height: delegation.start_height,
            end_height: delegation.end_height,
            total_sat: delegation.total_sat,
            staking_tx: delegation.staking_tx.to_vec(),
            slashing_tx: delegation.slashing_tx.to_vec(),
            delegator_slashing_sig: delegation.delegator_slashing_sig.to_vec(),
            covenant_sigs: delegation.covenant_sigs,
            staking_output_idx: delegation.staking_output_idx,
            unbonding_time: delegation.unbonding_time,
            undelegation_info: btc_undelegation_info.into(),
            params_version: delegation.params_version,
        })
    }
}

impl TryFrom<&ActiveBtcDelegation> for BtcDelegation {
    type Error = ContractError;

    fn try_from(delegation: &ActiveBtcDelegation) -> Result<Self, Self::Error> {
        BtcDelegation::try_from(delegation.clone())
    }
}

#[cw_serde]
pub struct UndelegationInfo {
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

impl From<BtcUndelegationInfo> for UndelegationInfo {
    fn from(info: BtcUndelegationInfo) -> Self {
        UndelegationInfo {
            unbonding_tx: info.unbonding_tx.to_vec(),
            delegator_unbonding_sig: info.delegator_unbonding_sig.to_vec(),
            covenant_unbonding_sig_list: info.covenant_unbonding_sig_list,
            slashing_tx: info.slashing_tx.to_vec(),
            delegator_slashing_sig: info.delegator_slashing_sig.to_vec(),
            covenant_slashing_sigs: info.covenant_slashing_sigs,
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

/// `FP_SET` is the calculated list of the active finality providers by height
pub const FP_SET: Map<u64, Vec<FinalityProviderInfo>> = Map::new("fp_set");
/// `TOTAL_POWER` is the total power of all finality providers
// FIXME: Store by height? Remove? Not currently being used in the contract
pub const TOTAL_POWER: Item<u64> = Item::new("total_power");

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
