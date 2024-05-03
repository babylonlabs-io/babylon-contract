/// BTC staking messages / API
/// The definitions here follow the same structure as the equivalent IBC protobuf message types,
/// defined in `packages/proto/src/gen/babylon.btcstaking.v1.rs`
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Decimal, StdError, StdResult};

type Bytes = Vec<u8>;

#[cw_serde]
/// btc_staking execution handlers
pub enum ExecuteMsg {
    /// BTC Staking operations.
    BtcStaking {
        new_fp: Vec<FinalityProvider>,
        slashed_fp: Vec<SlashedFinalityProvider>,
        active_del: Vec<ActiveBtcDelegation>,
        slashed_del: Vec<SlashedBtcDelegation>,
        unbonded_del: Vec<UnbondedBtcDelegation>,
    },
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
    /// master_pub_rand is the master public randomness of the finality provider
    /// encoded as a base58 string
    pub master_pub_rand: String,
    /// registered_epoch is the epoch when this finality provider is registered
    pub registered_epoch: u64,
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0, then the finality provider is not slashed
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0, then the finality provider is not slashed
    pub slashed_btc_height: u64,
    /// chain_id is the chain id of the chain the finality provider is operating on.
    /// If it's missing / empty, it's assumed the finality provider is operating in the Babylon chain.
    pub chain_id: String,
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
    const MAX_MONIKER_LENGTH: usize = 70;
    const MAX_IDENTITY_LENGTH: usize = 3000;
    const MAX_WEBSITE_LENGTH: usize = 140;
    const MAX_SECURITY_CONTACT_LENGTH: usize = 140;
    const MAX_DETAILS_LENGTH: usize = 280;

    pub fn validate(&self) -> StdResult<()> {
        self.ensure_field_lengths()
    }

    fn ensure_field_lengths(&self) -> StdResult<()> {
        if self.moniker.is_empty() {
            return Err(StdError::generic_err("Moniker cannot be empty"));
        }
        if self.moniker.len() > FinalityProviderDescription::MAX_MONIKER_LENGTH {
            return Err(StdError::generic_err(format!(
                "Invalid moniker length; got: {}, max: {}",
                self.moniker.len(),
                FinalityProviderDescription::MAX_MONIKER_LENGTH
            )));
        }

        if self.identity.len() > FinalityProviderDescription::MAX_IDENTITY_LENGTH {
            return Err(StdError::generic_err(format!(
                "Invalid identity length; got: {}, max: {}",
                self.identity.len(),
                FinalityProviderDescription::MAX_IDENTITY_LENGTH
            )));
        }

        if self.website.len() > FinalityProviderDescription::MAX_WEBSITE_LENGTH {
            return Err(StdError::generic_err(format!(
                "Invalid website length; got: {}, max: {}",
                self.website.len(),
                FinalityProviderDescription::MAX_WEBSITE_LENGTH
            )));
        }

        if self.security_contact.len() > FinalityProviderDescription::MAX_SECURITY_CONTACT_LENGTH {
            return Err(StdError::generic_err(format!(
                "Invalid security contact length; got: {}, max: {}",
                self.security_contact.len(),
                FinalityProviderDescription::MAX_SECURITY_CONTACT_LENGTH
            )));
        }

        if self.details.len() > FinalityProviderDescription::MAX_DETAILS_LENGTH {
            return Err(StdError::generic_err(format!(
                "Invalid details length; got: {}, max: {}",
                self.details.len(),
                FinalityProviderDescription::MAX_DETAILS_LENGTH
            )));
        }

        Ok(())
    }
}

/// PubKey defines a secp256k1 public key.
/// Key is the compressed form of the pubkey. The first byte is a 0x02 byte
/// if the y-coordinate is the lexicographically largest of the two associated with
/// the x-coordinate. Otherwise, the first byte is a 0x03.
/// This prefix is followed with the x-coordinate.
#[cw_serde]
pub struct PubKey {
    /// key is the compressed public key of the finality provider
    pub key: Bytes,
}

/// ProofOfPossession is the proof of possession that a Babylon secp256k1
/// secret key and a Bitcoin secp256k1 secret key are held by the same
/// person
#[cw_serde]
pub struct ProofOfPossession {
    /// btc_sig_type indicates the type of btc_sig in the pop
    pub btc_sig_type: i32,
    /// babylon_sig is the signature generated via sign(sk_babylon, pk_btc)
    pub babylon_sig: Bytes,
    /// btc_sig is the signature generated via sign(sk_btc, babylon_sig)
    /// the signature follows encoding in either BIP-340 spec or BIP-322 spec
    pub btc_sig: Bytes,
}

/// SlashedFinalityProvider is a packet sent from Consumer chain to Babylon
/// upon a finality provider is slashed on the Consumer chain
#[cw_serde]
pub struct SlashedFinalityProvider {
    /// btc_pk_hex is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// recovered_fp_btc_sk is the finality provider's BTC SK extracted due to slashing.
    /// This allows the consumer chain to verify the BTC delegation is indeed slashed
    pub recovered_fp_btc_sk: String,
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
    pub undelegation_info: Option<BtcUndelegationInfo>,
    /// params version used to validate the delegation
    pub params_version: u32,
}

/// CovenantAdaptorSignatures is a list adaptor signatures signed by the
/// covenant with different finality provider's public keys as encryption keys
#[cw_serde]
pub struct CovenantAdaptorSignatures {
    /// cov_pk is the public key of the covenant emulator, used as the public key of the adaptor signature
    pub cov_pk: Bytes,
    /// adaptor_sigs is a list of adaptor signatures, each encrypted by a restaked BTC finality provider's public key
    pub adaptor_sigs: Vec<Bytes>,
}

/// BTCUndelegationInfo provides all necessary info about the undeleagation
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

/// SignatureInfo is a BIP-340 signature together with its signer's BIP-340 PK
#[cw_serde]
pub struct SignatureInfo {
    pub pk: Bytes,
    pub sig: Bytes,
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
    pub unbonding_tx_sig: Bytes,
}
