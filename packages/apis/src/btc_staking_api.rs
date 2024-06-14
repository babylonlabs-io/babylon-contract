/// BTC staking messages / API
/// The definitions here follow the same structure as the equivalent IBC protobuf message types,
/// defined in `packages/proto/src/gen/babylon.btcstaking.v1.rs`
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Binary, Decimal};

use babylon_merkle::Proof;

/// Hash size in bytes
pub const HASH_SIZE: usize = 32;

#[cw_serde]
/// btc_staking execution handlers
pub enum ExecuteMsg {
    /// Change the admin
    UpdateAdmin { admin: Option<String> },
    /// BTC Staking operations
    BtcStaking {
        new_fp: Vec<NewFinalityProvider>,
        active_del: Vec<ActiveBtcDelegation>,
        slashed_del: Vec<SlashedBtcDelegation>,
        unbonded_del: Vec<UnbondedBtcDelegation>,
    },
    /// Committing a sequence of public randomness for EOTS
    // TODO: Move to its own module / contract
    CommitPublicRandomness {
        /// `fp_pubkey_hex` is the BTC PK of the finality provider that commits the public randomness
        fp_pubkey_hex: String,
        /// `start_height` is the start block height of the list of public randomness
        start_height: u64,
        /// `num_pub_rand` is the amount of public randomness committed
        num_pub_rand: u64,
        /// `commitment` is the commitment of these public randomness values.
        /// Currently, it's the root of the Merkle tree that includes the public randomness
        commitment: Binary,
        /// `signature` is the signature on (start_height || num_pub_rand || commitment) signed by
        /// the SK corresponding to `fp_pubkey_hex`.
        /// This prevents others committing public randomness on behalf of `fp_pubkey_hex`
        signature: Binary,
    },
    /// Submit Finality Signature.
    ///
    /// This is a message that can be called by a finality provider to submit their finality
    /// signature to the Consumer chain.
    /// The signature is verified by the Consumer chain using the finality provider's public key
    ///
    /// This message is equivalent to the `MsgAddFinalitySig` message in the Babylon finality protobuf
    /// defs.
    // TODO: Move to its own module / contract
    SubmitFinalitySignature {
        fp_pubkey_hex: String,
        height: u64,
        pub_rand: Binary,
        proof: Proof,
        block_hash: Binary,
        signature: Binary,
    },
}

#[cw_serde]
pub enum SudoMsg {
    /// The SDK should call SudoMsg::BeginBlock{} once per block (in BeginBlock).
    /// It allows the BTC staking contract to index the BTC height, and update the power
    /// distribution of the active Finality Providers.
    BeginBlock(BeginBlockMsg),
    /// The SDK should call SudoMsg::EndBlock{} once per block (in EndBlock).
    /// It allows the BTC staking contract to tally all non-finalised blocks.
    EndBlock(EndBlockMsg),
}

#[cw_serde]
pub struct BeginBlockMsg {
    height: i64,
    hash_hex: String,
    time: String,
    chain_id: String,
    app_hash_hex: String,
}

#[cw_serde]
pub struct EndBlockMsg {
    height: i64,
    hash_hex: String,
    time: String,
    chain_id: String,
    app_hash_hex: String,
}

#[cw_serde]
pub struct NewFinalityProvider {
    /// description defines the description terms for the finality provider
    pub description: Option<FinalityProviderDescription>,
    /// commission defines the commission rate of the finality provider.
    pub commission: Decimal,
    /// babylon_pk is the Babylon secp256k1 PK of this finality provider
    pub babylon_pk: Option<PubKey>,
    /// btc_pk_hex is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// pop is the proof of possession of the babylon_pk and btc_pk
    pub pop: Option<ProofOfPossession>,
    /// consumer_id is the ID of the consumer that the finality provider is operating on.
    pub consumer_id: String,
}

#[cw_serde]
pub struct FinalityProvider {
    /// description defines the description terms for the finality provider
    pub description: Option<FinalityProviderDescription>,
    /// commission defines the commission rate of the finality provider.
    pub commission: Decimal,
    /// babylon_pk is the Babylon secp256k1 PK of this finality provider
    pub babylon_pk: Option<PubKey>,
    /// btc_pk_hex is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// pop is the proof of possession of the babylon_pk and btc_pk
    pub pop: Option<ProofOfPossession>,
    /// slashed_height is the height on which the finality provider is slashed
    pub slashed_height: u64,
    /// slashed_btc_height is the BTC height on which the finality provider is slashed
    pub slashed_btc_height: u64,
    /// consumer_id is the ID of the consumer that the finality provider is operating on.
    pub consumer_id: String,
}

impl From<&NewFinalityProvider> for FinalityProvider {
    fn from(new_fp: &NewFinalityProvider) -> Self {
        FinalityProvider {
            description: new_fp.description.clone(),
            commission: new_fp.commission,
            babylon_pk: new_fp.babylon_pk.clone(),
            btc_pk_hex: new_fp.btc_pk_hex.clone(),
            pop: new_fp.pop.clone(),
            slashed_height: 0,
            slashed_btc_height: 0,
            consumer_id: new_fp.consumer_id.clone(),
        }
    }
}

#[cw_serde]
pub struct FinalityProviderDescription {
    /// moniker is the name of the finality provider
    pub moniker: String,
    /// identity is the identity of the finality provider
    pub identity: String,
    /// website is the website of the finality provider
    pub website: String,
    /// security_contact is the security contact of the finality provider
    pub security_contact: String,
    /// details is the details of the finality provider
    pub details: String,
}

impl FinalityProviderDescription {
    /// Description field lengths
    pub const MAX_MONIKER_LENGTH: usize = 70;
    pub const MAX_IDENTITY_LENGTH: usize = 3000;
    pub const MAX_WEBSITE_LENGTH: usize = 140;
    pub const MAX_SECURITY_CONTACT_LENGTH: usize = 140;
    pub const MAX_DETAILS_LENGTH: usize = 280;
}

/// PubKey defines a secp256k1 public key.
/// Key is the compressed form of the pubkey. The first byte is a 0x02 byte
/// if the y-coordinate is the lexicographically largest of the two associated with
/// the x-coordinate. Otherwise, the first byte is a 0x03.
/// This prefix is followed with the x-coordinate.
#[cw_serde]
pub struct PubKey {
    /// key is the compressed public key of the finality provider
    pub key: Binary,
}

/// ProofOfPossession is the proof of possession that a Babylon secp256k1
/// secret key and a Bitcoin secp256k1 secret key are held by the same
/// person
#[cw_serde]
pub struct ProofOfPossession {
    /// btc_sig_type indicates the type of btc_sig in the pop
    pub btc_sig_type: i32,
    /// babylon_sig is the signature generated via sign(sk_babylon, pk_btc)
    pub babylon_sig: Binary,
    /// btc_sig is the signature generated via sign(sk_btc, babylon_sig)
    /// the signature follows encoding in either BIP-340 spec or BIP-322 spec
    pub btc_sig: Binary,
}

/// BTCDelegationStatus is the status of a delegation.
/// The state transition path is PENDING -> ACTIVE -> UNBONDED with two possibilities:
///     1. The typical path when time-lock of staking transaction expires.
///     2. The path when staker requests an early undelegation through a BtcStaking
///     UnbondedBtcDelegation message.
#[cw_serde]
pub enum BTCDelegationStatus {
    /// PENDING defines a delegation waiting for covenant signatures to become active
    PENDING = 0,
    /// ACTIVE defines a delegation that has voting power
    ACTIVE = 1,
    /// UNBONDED defines a delegation that no longer has voting power:
    /// - Either reaching the end of staking transaction time-lock.
    /// - Or by receiving an unbonding tx with signatures from staker and covenant committee
    UNBONDED = 2,
    /// ANY is any of the status above
    ANY = 3,
}

/// ActiveBTCDelegation is a message sent when a BTC delegation newly receives covenant signatures
/// and thus becomes active
#[cw_serde]
pub struct ActiveBtcDelegation {
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
    pub staking_tx: Binary,
    /// slashing_tx is the slashing tx
    pub slashing_tx: Binary,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e. SK corresponding to btc_pk) as string hex.
    /// It will be a part of the witness for the staking tx output.
    pub delegator_slashing_sig: Binary,
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
    pub undelegation_info: Option<BtcUndelegationInfo>,
    /// params version used to validate the delegation
    pub params_version: u32,
}

impl ActiveBtcDelegation {
    pub fn is_active(&self) -> bool {
        // TODO: Implement full delegation status checks (needs BTC height)
        // self.get_status(btc_height, w) == BTCDelegationStatus::ACTIVE
        !self.is_unbonded_early()
    }

    fn is_unbonded_early(&self) -> bool {
        if let Some(undelegation_info) = &self.undelegation_info {
            !undelegation_info.delegator_unbonding_sig.is_empty()
        } else {
            // Can only happen if the state is corrupted.
            // Every BTC delegation has to have undelegation info
            true // Consider broken delegations as unbonded
        }
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

/// CovenantAdaptorSignatures is a list adaptor signatures signed by the
/// covenant with different finality provider's public keys as encryption keys
#[cw_serde]
pub struct CovenantAdaptorSignatures {
    /// cov_pk is the public key of the covenant emulator, used as the public key of the adaptor signature
    pub cov_pk: Binary,
    /// adaptor_sigs is a list of adaptor signatures, each encrypted by a restaked BTC finality provider's public key
    pub adaptor_sigs: Vec<Binary>,
}

/// BTCUndelegationInfo provides all necessary info about the undeleagation
#[cw_serde]
pub struct BtcUndelegationInfo {
    /// unbonding_tx is the transaction which will transfer the funds from staking
    /// output to unbonding output. Unbonding output will usually have lower timelock
    /// than staking output.
    pub unbonding_tx: Binary,
    /// delegator_unbonding_sig is the signature on the unbonding tx
    /// by the delegator (i.e. SK corresponding to btc_pk).
    /// It effectively proves that the delegator wants to unbond and thus
    /// Babylon will consider this BTC delegation unbonded. Delegator's BTC
    /// on Bitcoin will be unbonded after time-lock.
    pub delegator_unbonding_sig: Binary,
    /// covenant_unbonding_sig_list is the list of signatures on the unbonding tx
    /// by covenant members
    pub covenant_unbonding_sig_list: Vec<SignatureInfo>,
    /// slashing_tx is the unbonding slashing tx
    pub slashing_tx: Binary,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e. SK corresponding to btc_pk).
    /// It will be a part of the witness for the unbonding tx output.
    pub delegator_slashing_sig: Binary,
    /// covenant_slashing_sigs is a list of adaptor signatures on the
    /// unbonding slashing tx by each covenant member
    /// It will be a part of the witness for the staking tx output.
    pub covenant_slashing_sigs: Vec<CovenantAdaptorSignatures>,
}

/// SignatureInfo is a BIP-340 signature together with its signer's BIP-340 PK
#[cw_serde]
pub struct SignatureInfo {
    pub pk: Binary,
    pub sig: Binary,
}

/// SlashedBTCDelegation is a packet sent from Babylon to the Consumer chain about a slashed BTC
/// delegation re-staked to >=1 of the Consumer chain's finality providers
#[cw_serde]
pub struct SlashedBtcDelegation {
    /// staking tx hash of the BTC delegation. It uniquely identifies a BTC delegation
    pub staking_tx_hash: String,
    /// recovered_fp_btc_sk is the extracted BTC SK of the finality provider on this Consumer chain
    pub recovered_fp_btc_sk: String,
}

/// UnbondedBTCDelegation is sent from Babylon to the Consumer chain upon an early unbonded BTC
/// delegation
#[cw_serde]
pub struct UnbondedBtcDelegation {
    /// staking tx hash of the BTC delegation. It uniquely identifies a BTC delegation
    pub staking_tx_hash: String,
    /// unbonding_tx_sig is the signature on the unbonding tx signed by the BTC delegator
    /// It proves that the BTC delegator wants to unbond
    pub unbonding_tx_sig: Binary,
}
