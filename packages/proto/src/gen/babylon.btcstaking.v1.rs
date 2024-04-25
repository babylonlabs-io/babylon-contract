// @generated
/// ProofOfPossession is the proof of possession that a Babylon secp256k1
/// secret key and a Bitcoin secp256k1 secret key are held by the same
/// person
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofOfPossession {
    /// btc_sig_type indicates the type of btc_sig in the pop
    #[prost(enumeration="BtcSigType", tag="1")]
    pub btc_sig_type: i32,
    /// babylon_sig is the signature generated via sign(sk_babylon, pk_btc)
    #[prost(bytes="bytes", tag="2")]
    pub babylon_sig: ::prost::bytes::Bytes,
    /// btc_sig is the signature generated via sign(sk_btc, babylon_sig)
    /// the signature follows encoding in either BIP-340 spec or BIP-322 spec
    #[prost(bytes="bytes", tag="3")]
    pub btc_sig: ::prost::bytes::Bytes,
}
/// BTCSigType indicates the type of btc_sig in a pop
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum BtcSigType {
    /// BIP340 means the btc_sig will follow the BIP-340 encoding
    Bip340 = 0,
    /// BIP322 means the btc_sig will follow the BIP-322 encoding
    Bip322 = 1,
    /// ECDSA means the btc_sig will follow the ECDSA encoding
    /// ref: <https://github.com/okx/js-wallet-sdk/blob/a57c2acbe6ce917c0aa4e951d96c4e562ad58444/packages/coin-bitcoin/src/BtcWallet.ts#L331>
    Ecdsa = 2,
}
impl BtcSigType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            BtcSigType::Bip340 => "BIP340",
            BtcSigType::Bip322 => "BIP322",
            BtcSigType::Ecdsa => "ECDSA",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "BIP340" => Some(Self::Bip340),
            "BIP322" => Some(Self::Bip322),
            "ECDSA" => Some(Self::Ecdsa),
            _ => None,
        }
    }
}
/// SignatureInfo is a BIP-340 signature together with its signer's BIP-340 PK
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureInfo {
    #[prost(bytes="bytes", tag="1")]
    pub pk: ::prost::bytes::Bytes,
    #[prost(bytes="bytes", tag="2")]
    pub sig: ::prost::bytes::Bytes,
}
/// CovenantAdaptorSignatures is a list adaptor signatures signed by the
/// covenant with different finality provider's public keys as encryption keys
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CovenantAdaptorSignatures {
    /// cov_pk is the public key of the covenant emulator, used as the public key of the adaptor signature
    #[prost(bytes="bytes", tag="1")]
    pub cov_pk: ::prost::bytes::Bytes,
    /// adaptor_sigs is a list of adaptor signatures, each encrypted by a restaked BTC finality provider's public key
    #[prost(bytes="bytes", repeated, tag="2")]
    pub adaptor_sigs: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
}
/// BTCStakingIBCPacket is an IBC packet carrying a set of events related
/// to BTC staking for a particular consumer chain
/// It will be constructed and sent upon `EndBlock` of ZoneConcierge
/// (if there are any BTC staking events for a consumer chain)
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcStakingIbcPacket {
    #[prost(message, repeated, tag="1")]
    pub new_fp: ::prost::alloc::vec::Vec<NewFinalityProvider>,
    #[prost(message, repeated, tag="2")]
    pub slashed_fp: ::prost::alloc::vec::Vec<SlashedFinalityProvider>,
    #[prost(message, repeated, tag="3")]
    pub active_del: ::prost::alloc::vec::Vec<ActiveBtcDelegation>,
    #[prost(message, repeated, tag="4")]
    pub slashed_del: ::prost::alloc::vec::Vec<SlashedBtcDelegation>,
    #[prost(message, repeated, tag="5")]
    pub unbonded_del: ::prost::alloc::vec::Vec<UnbondedBtcDelegation>,
}
/// NewFinalityProvider is an IBC packet sent from Babylon to consumer chain
/// upon a newly registered finality provider on this consumer chain
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewFinalityProvider {
    /// description defines the description terms for the finality provider.
    #[prost(message, optional, tag="1")]
    pub description: ::core::option::Option<cosmos_sdk_proto::cosmos::staking::v1beta1::Description>,
    /// commission defines the commission rate of the finality provider.
    /// It forms as a string converted from "cosmossdk.io/math.LegacyDec"
    #[prost(string, tag="2")]
    pub commission: ::prost::alloc::string::String,
    /// babylon_pk is the Babylon secp256k1 PK of this finality provider
    #[prost(message, optional, tag="3")]
    pub babylon_pk: ::core::option::Option<cosmos_sdk_proto::cosmos::crypto::secp256k1::PubKey>,
    /// btc_pk_hex is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec in hex format
    #[prost(string, tag="4")]
    pub btc_pk_hex: ::prost::alloc::string::String,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="5")]
    pub pop: ::core::option::Option<ProofOfPossession>,
    /// master_pub_rand is the master public randomness of the finality provider
    /// encoded as a base58 string
    #[prost(string, tag="6")]
    pub master_pub_rand: ::prost::alloc::string::String,
    /// registered_epoch is the epoch when this finality provider is registered
    #[prost(uint64, tag="7")]
    pub registered_epoch: u64,
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="8")]
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="9")]
    pub slashed_btc_height: u64,
    /// chain_id is the chain id of the chain the finality provider is operating on.
    /// If it's missing / empty, it's assumed the finality provider is operating in the Babylon chain.
    #[prost(string, tag="10")]
    pub chain_id: ::prost::alloc::string::String,
}
/// SlashedFinalityProvider is an IBC packet sent from consumer chain to Babylon
/// upon a finality provider is slashed on the consumer chain
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SlashedFinalityProvider {
    /// btc_pk_hex is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec in hex format
    #[prost(string, tag="1")]
    pub btc_pk_hex: ::prost::alloc::string::String,
    /// recovered_fp_btc_sk is the finality provider's BTC SK extracted due to slashing
    /// this allows the consumer chain to verify the BTC delegation is indeed slashed
    #[prost(string, tag="2")]
    pub recovered_fp_btc_sk: ::prost::alloc::string::String,
}
/// ActiveBTCDelegation is an IBC packet sent from Babylon to consumer chain
/// upon a BTC delegation newly receives covenant signatures and thus becomes active
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActiveBtcDelegation {
    /// btc_pk_hex is the Bitcoin secp256k1 PK of this BTC delegation
    /// the PK follows encoding in BIP-340 spec in hex format
    #[prost(string, tag="1")]
    pub btc_pk_hex: ::prost::alloc::string::String,
    /// fp_btc_pk_list is the list of BIP-340 PKs of the finality providers that
    /// this BTC delegation delegates to
    #[prost(string, repeated, tag="2")]
    pub fp_btc_pk_list: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// start_height is the start BTC height of the BTC delegation
    /// it is the start BTC height of the timelock
    #[prost(uint64, tag="3")]
    pub start_height: u64,
    /// end_height is the end height of the BTC delegation
    /// it is the end BTC height of the timelock - w
    #[prost(uint64, tag="4")]
    pub end_height: u64,
    /// total_sat is the total amount of BTC stakes in this delegation
    /// quantified in satoshi
    #[prost(uint64, tag="5")]
    pub total_sat: u64,
    /// staking_tx is the staking tx
    #[prost(bytes="bytes", tag="6")]
    pub staking_tx: ::prost::bytes::Bytes,
    /// slashing_tx is the slashing tx
    #[prost(bytes="bytes", tag="7")]
    pub slashing_tx: ::prost::bytes::Bytes,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk) as string hex.
    /// It will be a part of the witness for the staking tx output.
    #[prost(bytes="bytes", tag="8")]
    pub delegator_slashing_sig: ::prost::bytes::Bytes,
    /// covenant_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="9")]
    pub covenant_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
    /// staking_output_idx is the index of the staking output in the staking tx
    #[prost(uint32, tag="10")]
    pub staking_output_idx: u32,
    /// unbonding_time used in unbonding output timelock path and in slashing transactions
    /// change outputs
    #[prost(uint32, tag="13")]
    pub unbonding_time: u32,
    /// undelegation_info is the undelegation info of this delegation.
    #[prost(message, optional, tag="14")]
    pub undelegation_info: ::core::option::Option<BtcUndelegationInfo>,
    /// params version used to validate delegation
    #[prost(uint32, tag="15")]
    pub params_version: u32,
}
/// BTCUndelegationInfo provides all necessary info about the undeleagation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcUndelegationInfo {
    /// unbonding_tx is the transaction which will transfer the funds from staking
    /// output to unbonding output. Unbonding output will usually have lower timelock
    /// than staking output.
    #[prost(bytes="bytes", tag="1")]
    pub unbonding_tx: ::prost::bytes::Bytes,
    /// delegator_unbonding_sig is the signature on the unbonding tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It effectively proves that the delegator wants to unbond and thus
    /// Babylon will consider this BTC delegation unbonded. Delegator's BTC
    /// on Bitcoin will be unbonded after timelock.
    #[prost(bytes="bytes", tag="2")]
    pub delegator_unbonding_sig: ::prost::bytes::Bytes,
    /// covenant_unbonding_sig_list is the list of signatures on the unbonding tx
    /// by covenant members
    #[prost(message, repeated, tag="3")]
    pub covenant_unbonding_sig_list: ::prost::alloc::vec::Vec<SignatureInfo>,
    /// slashing_tx is the unbonding slashing tx
    #[prost(bytes="bytes", tag="4")]
    pub slashing_tx: ::prost::bytes::Bytes,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It will be a part of the witness for the unbonding tx output.
    #[prost(bytes="bytes", tag="5")]
    pub delegator_slashing_sig: ::prost::bytes::Bytes,
    /// covenant_slashing_sigs is a list of adaptor signatures on the
    /// unbonding slashing tx by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="6")]
    pub covenant_slashing_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
}
/// SlashedBTCDelegation is an IBC packet sent from Babylon to consumer chain
/// about a slashed BTC delegation restaked to >=1 of this consumer chain's 
/// finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SlashedBtcDelegation {
    /// staking tx hash of the BTC delegation. It uniquely identifies a BTC delegation
    #[prost(string, tag="1")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// recovered_fp_btc_sk is the extracted BTC SK of the finality provider on
    /// this consumer chain
    /// this allows the consumer chain to verify the BTC delegation is indeed slashed
    #[prost(string, tag="2")]
    pub recovered_fp_btc_sk: ::prost::alloc::string::String,
}
/// UnbondedBTCDelegation is an IBC packet sent from Babylon to consumer chain
/// upon an early unbonded BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnbondedBtcDelegation {
    /// staking tx hash of the BTC delegation. It uniquely identifies a BTC delegation
    #[prost(string, tag="1")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// unbonding_tx_sig is the signature on the unbonding tx signed by the BTC delegator
    /// It proves that the BTC delegator wants to unbond
    #[prost(bytes="bytes", tag="2")]
    pub unbonding_tx_sig: ::prost::bytes::Bytes,
}
// @@protoc_insertion_point(module)
