use std::cmp::Ordering;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::Uint256;

/// Points alignment is how many points should be added / subtracted from points calculated per
/// delegation due to stake changes. It has to be a signed type - using `Uint256` here as a "fake"
/// type. So for calculations it is shifted - the real value stored is `points_alignment - Uint256::MAX / 2`
/// - this is not ideal, but it makes calculations always fit in U256.
#[cw_serde]
#[derive(Copy)]
pub struct PointsAlignment(Uint256);

impl PointsAlignment {
    pub fn new() -> Self {
        Self(Uint256::MAX >> 1)
    }

    /// Align points with alignment
    pub fn align(self, points: Uint256) -> Uint256 {
        match self.0.cmp(&(Uint256::MAX >> 1)) {
            // Points alignment negative - first we need to add alignment and then add offset
            // to avoid exceeding limit
            Ordering::Less => points + self.0 - (Uint256::MAX >> 1),
            // Points alignment is positive - first we reduce it by offset and then add to the
            // points
            Ordering::Greater => points + (self.0 - (Uint256::MAX >> 1)),
            // Alignment is `0`, no math to be done
            Ordering::Equal => points,
        }
    }

    /// Modify points alignment due to increased delegation - increasing weight immediately "adds"
    /// points distributed to the owner of this delegation, so they need to be reduced
    ///
    /// * amount - amount just delegated
    /// * ppd - points per delegation right now
    pub fn stake_increased(&mut self, amount: u64, ppd: Uint256) {
        self.0 -= Uint256::from(amount) * ppd;
    }

    /// Modify points alignment due to decreased delegation - decreasing weight immediately "removes"
    /// points distributed to the owner of this delegation, so they need to be increased
    ///
    /// * amount - amount just delegated
    /// * ppd - points per delegation right now
    pub fn stake_decreased(&mut self, amount: u64, ppd: Uint256) {
        self.0 += Uint256::from(amount) * ppd;
    }
}

impl Default for PointsAlignment {
    fn default() -> Self {
        Self::new()
    }
}
