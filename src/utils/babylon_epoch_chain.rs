use babylon_bitcoin::BlockHeader;
use babylon_bitcoin::Uint256;
use babylon_proto::babylon::btccheckpoint::v1::TransactionInfo;
use babylon_proto::babylon::checkpointing::v1::RawCheckpoint;
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::ProofEpochSealed;
use core::panic;

pub const NUM_BTC_TXS: usize = 2;

/// verify_epoch_sealed ensures the given raw checkpoint is sealed, i.e., BLS-signed,
/// by the validator set of the given epoch
/// reference implementation: https://github.com/babylonchain/babylon/blob/v0.5.0/x/zoneconcierge/keeper/proof_epoch_sealed.go
pub fn verify_epoch_sealed(
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof: &ProofEpochSealed,
) -> Result<(), String> {
    panic!("TODO: implement me")
}

/// verify_checkpoint_submitted ensures the given raw checkpoint is submitted, i.e.,
/// whose two txs are in the given 2 BTC headers.
/// reference implementation: https://github.com/babylonchain/babylon/blob/v0.5.0/x/zoneconcierge/keeper/proof_epoch_submitted.go
pub fn verify_checkpoint_submitted(
    raw_ckpt: &RawCheckpoint,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
    btc_headers: &[BlockHeader; NUM_BTC_TXS],
    pow_limit: &Uint256,
    babylon_tag: &[u8],
) -> Result<(), String> {
    panic!("TODO: implement me")
}
