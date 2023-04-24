use bitvec::prelude::*;

impl ValidatorWithBlsKeySet {
    pub fn get_total_power(&self) -> u64 {
        let mut total_power: u64 = 0;
        for val in self.val_set.iter() {
            total_power += val.voting_power;
        }
        return total_power;
    }

    pub fn find_subset_with_power_sum(
        &self,
        bitmap_bytes: &[u8],
    ) -> Result<(ValidatorWithBlsKeySet, u64), String> {
        let mut sum: u64 = 0;
        let mut val_subset: Vec<ValidatorWithBlsKey> = vec![];

        // initialise bitmap
        let bitmap = bitmap_bytes.view_bits::<Lsb0>();
        let bitmap_size = bitmap.len() * 8;

        // ensure bitmap is big enough to contain ks
        if bitmap_size < self.val_set.len() {
            return Err(format!("bitmap (with {} bits) is not large enough to contain the validator set with size {}", bitmap_size, self.val_set.len()));
        }

        for i in 0..self.val_set.len() {
            let bit = *bitmap.get(i).unwrap();
            if bit {
                let voted_val = self.val_set.get(i).unwrap();
                val_subset.push(voted_val.clone());
                sum += voted_val.voting_power;
            }
        }

        let subset = ValidatorWithBlsKeySet {
            val_set: val_subset,
        };

        Ok((subset, sum))
    }
}

impl RawCheckpoint {
    pub fn signed_msg(&self) -> Vec<u8> {
        let mut msg_bytes = self.epoch_num.to_be_bytes().to_vec();
        msg_bytes.extend(&self.last_commit_hash);
        return msg_bytes;
    }
}
