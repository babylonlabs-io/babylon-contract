use crate::state::points_alignment::PointsAlignment;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{CanonicalAddr, Order, StdResult, Storage, Uint128};
use cw_storage_plus::{Index, IndexList, IndexedMap, KeyDeserialize, MultiIndex};

/// Single delegation related information - entry per `(staking hash, finality provider public key)`
/// pair, including distribution alignment
#[cw_serde]
pub struct Delegation {
    /// The delegator's canonical address
    pub staker_addr: CanonicalAddr,
    /// How many satoshis the user stakes in this delegation
    pub stake: u64,
    /// How many points should be added / subtracted from points calculated per delegation due to
    /// delegation changes.
    pub points_alignment: PointsAlignment,
    /// Rewards already withdrawn by this user
    pub withdrawn_funds: Uint128,
}

pub struct DelegationIndexes<'a> {
    // Last type param defines the pk deserialization type
    #[allow(clippy::type_complexity)]
    pub rev: MultiIndex<'a, (String, Vec<u8>), Delegation, (Vec<u8>, String)>,
    // Delegations by staker's (raw, canonical) address
    pub staker: MultiIndex<'a, Vec<u8>, Delegation, (Vec<u8>, String)>,
}

impl<'a> IndexList<Delegation> for DelegationIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<Delegation>> + '_> {
        let v: Vec<&dyn Index<Delegation>> = vec![&self.rev];
        Box::new(v.into_iter())
    }
}

pub struct Delegations<'a> {
    pub delegation: IndexedMap<(&'a [u8], &'a str), Delegation, DelegationIndexes<'a>>,
}

impl<'a> Delegations<'a> {
    fn deserialize_pk(pk: &[u8]) -> (Vec<u8>, String) {
        <(Vec<u8>, String)>::from_slice(pk).unwrap() // mustn't fail
    }

    pub fn new(
        storage_key: &'static str,
        fp_subkey: &'static str,
        staker_subkey: &'static str,
    ) -> Self {
        let indexes = DelegationIndexes {
            rev: MultiIndex::new(
                |pk, _| {
                    let (staking_hash, fp) = Self::deserialize_pk(pk);
                    (fp, staking_hash)
                },
                storage_key,
                fp_subkey,
            ),
            staker: MultiIndex::new(
                |_, del| del.staker_addr.to_vec(),
                storage_key,
                staker_subkey,
            ),
        };
        let delegations = IndexedMap::new(storage_key, indexes);

        Self {
            delegation: delegations,
        }
    }

    pub fn delegations_by_fp(
        &self,
        storage: &dyn Storage,
        fp: &str,
    ) -> StdResult<Vec<(Vec<u8>, Delegation)>> {
        self.delegation
            .idx
            .rev
            .sub_prefix(fp.to_string())
            .range(storage, None, None, Order::Ascending)
            .map(|item| {
                let ((hash, _), del) = item?;
                Ok((hash, del))
            })
            .collect::<StdResult<Vec<(Vec<u8>, Delegation)>>>()
    }
}

const DELEGATIONS_KEY: &str = "delegations";
const FP_SUBKEY: &str = "fp";
const STAKER_SUBKEY: &str = "staker";

/// Indexed map for delegations and finality providers.
pub fn delegations<'a>() -> Delegations<'a> {
    Delegations::new(DELEGATIONS_KEY, FP_SUBKEY, STAKER_SUBKEY)
}
