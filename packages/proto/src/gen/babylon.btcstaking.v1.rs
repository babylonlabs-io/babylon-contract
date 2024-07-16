// @generated
/// ProofOfPossessionBTC is the proof of possession that a Babylon
/// address and a Bitcoin secp256k1 secret key are held by the same
/// person
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofOfPossessionBtc {
    /// btc_sig_type indicates the type of btc_sig in the pop
    #[prost(enumeration="BtcSigType", tag="1")]
    pub btc_sig_type: i32,
    /// btc_sig is the signature generated via sign(sk_btc, babylon_staker_address)
    /// the signature follows encoding in either BIP-340 spec or BIP-322 spec
    #[prost(bytes="bytes", tag="2")]
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
/// BTCDelegation defines a BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcDelegation {
    /// staker_addr is the address to receive rewards from BTC delegation.
    #[prost(string, tag="1")]
    pub staker_addr: ::prost::alloc::string::String,
    /// btc_pk is the Bitcoin secp256k1 PK of this BTC delegation
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="bytes", tag="2")]
    pub btc_pk: ::prost::bytes::Bytes,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="3")]
    pub pop: ::core::option::Option<ProofOfPossessionBtc>,
    /// fp_btc_pk_list is the list of BIP-340 PKs of the finality providers that
    /// this BTC delegation delegates to
    /// If there is more than 1 PKs, then this means the delegation is restaked
    /// to multiple finality providers
    #[prost(bytes="bytes", repeated, tag="4")]
    pub fp_btc_pk_list: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    /// start_height is the start BTC height of the BTC delegation
    /// it is the start BTC height of the timelock
    #[prost(uint64, tag="5")]
    pub start_height: u64,
    /// end_height is the end height of the BTC delegation
    /// it is the end BTC height of the timelock - w
    #[prost(uint64, tag="6")]
    pub end_height: u64,
    /// total_sat is the total amount of BTC stakes in this delegation
    /// quantified in satoshi
    #[prost(uint64, tag="7")]
    pub total_sat: u64,
    /// staking_tx is the staking tx
    #[prost(bytes="bytes", tag="8")]
    pub staking_tx: ::prost::bytes::Bytes,
    /// staking_output_idx is the index of the staking output in the staking tx
    #[prost(uint32, tag="9")]
    pub staking_output_idx: u32,
    /// slashing_tx is the slashing tx
    /// It is partially signed by SK corresponding to btc_pk, but not signed by
    /// finality provider or covenant yet.
    #[prost(bytes="bytes", tag="10")]
    pub slashing_tx: ::prost::bytes::Bytes,
    /// delegator_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It will be a part of the witness for the staking tx output.
    #[prost(bytes="bytes", tag="11")]
    pub delegator_sig: ::prost::bytes::Bytes,
    /// covenant_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="12")]
    pub covenant_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
    /// unbonding_time describes how long the funds will be locked either in unbonding output
    /// or slashing change output
    #[prost(uint32, tag="13")]
    pub unbonding_time: u32,
    /// btc_undelegation is the information about the early unbonding path of the BTC delegation
    #[prost(message, optional, tag="14")]
    pub btc_undelegation: ::core::option::Option<BtcUndelegation>,
    /// version of the params used to validate the delegation
    #[prost(uint32, tag="15")]
    pub params_version: u32,
}
/// BTCUndelegation contains the information about the early unbonding path of the BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcUndelegation {
    /// unbonding_tx is the transaction which will transfer the funds from staking
    /// output to unbonding output. Unbonding output will usually have lower timelock
    /// than staking output.
    #[prost(bytes="bytes", tag="1")]
    pub unbonding_tx: ::prost::bytes::Bytes,
    /// slashing_tx is the slashing tx for unbonding transactions
    /// It is partially signed by SK corresponding to btc_pk, but not signed by
    /// finality provider or covenant yet.
    #[prost(bytes="bytes", tag="2")]
    pub slashing_tx: ::prost::bytes::Bytes,
    /// delegator_unbonding_sig is the signature on the unbonding tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It effectively proves that the delegator wants to unbond and thus
    /// Babylon will consider this BTC delegation unbonded. Delegator's BTC
    /// on Bitcoin will be unbonded after timelock
    #[prost(bytes="bytes", tag="3")]
    pub delegator_unbonding_sig: ::prost::bytes::Bytes,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It will be a part of the witness for the unbonding tx output.
    #[prost(bytes="bytes", tag="4")]
    pub delegator_slashing_sig: ::prost::bytes::Bytes,
    /// covenant_slashing_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="5")]
    pub covenant_slashing_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
    /// covenant_unbonding_sig_list is the list of signatures on the unbonding tx
    /// by covenant members
    /// It must be provided after processing undelegate message by Babylon
    #[prost(message, repeated, tag="6")]
    pub covenant_unbonding_sig_list: ::prost::alloc::vec::Vec<SignatureInfo>,
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
/// Params defines the parameters for the module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    /// covenant_pks is the list of public keys held by the covenant committee
    /// each PK follows encoding in BIP-340 spec on Bitcoin
    #[prost(bytes="bytes", repeated, tag="1")]
    pub covenant_pks: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    /// covenant_quorum is the minimum number of signatures needed for the covenant
    /// multisignature
    #[prost(uint32, tag="2")]
    pub covenant_quorum: u32,
    /// slashing address is the address that the slashed BTC goes to
    /// the address is in string on Bitcoin
    #[prost(string, tag="3")]
    pub slashing_address: ::prost::alloc::string::String,
    /// min_slashing_tx_fee_sat is the minimum amount of tx fee (quantified
    /// in Satoshi) needed for the pre-signed slashing tx
    /// TODO: change to satoshi per byte?
    #[prost(int64, tag="4")]
    pub min_slashing_tx_fee_sat: i64,
    /// min_commission_rate is the chain-wide minimum commission rate that a finality provider can charge their delegators
    #[prost(string, tag="5")]
    pub min_commission_rate: ::prost::alloc::string::String,
    /// slashing_rate determines the portion of the staked amount to be slashed,
    /// expressed as a decimal (e.g., 0.5 for 50%).
    #[prost(string, tag="6")]
    pub slashing_rate: ::prost::alloc::string::String,
    /// max_active_finality_providers is the maximum number of active finality providers in the BTC staking protocol
    #[prost(uint32, tag="7")]
    pub max_active_finality_providers: u32,
    /// min_unbonding_time is the minimum time for unbonding transaction timelock in BTC blocks
    #[prost(uint32, tag="8")]
    pub min_unbonding_time: u32,
    /// min_unbonding_rate is the minimum amount of BTC that are required in unbonding
    /// output, expressed as a fraction of staking output
    /// example: if min_unbonding_rate=0.9, then the unbonding output value
    /// must be at least 90% of staking output, for staking request to be considered
    /// valid
    #[prost(string, tag="9")]
    pub min_unbonding_rate: ::prost::alloc::string::String,
}
/// BTCStakingIBCPacket is an IBC packet sent from Babylon to a consumer
/// It carries a set of events related to BTC staking for a given consumer
/// It will be constructed and sent upon `EndBlock` of ZoneConcierge
/// (if there are any BTC staking events for a consumer)
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcStakingIbcPacket {
    #[prost(message, repeated, tag="1")]
    pub new_fp: ::prost::alloc::vec::Vec<NewFinalityProvider>,
    #[prost(message, repeated, tag="2")]
    pub active_del: ::prost::alloc::vec::Vec<ActiveBtcDelegation>,
    #[prost(message, repeated, tag="3")]
    pub slashed_del: ::prost::alloc::vec::Vec<SlashedBtcDelegation>,
    #[prost(message, repeated, tag="4")]
    pub unbonded_del: ::prost::alloc::vec::Vec<UnbondedBtcDelegation>,
}
/// NewFinalityProvider is an IBC packet sent from Babylon to consumer
/// upon a newly registered finality provider on this consumer
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
    /// addr is the bech32 address identifier of the finality provider.
    #[prost(string, tag="3")]
    pub addr: ::prost::alloc::string::String,
    /// btc_pk_hex is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec in hex format
    #[prost(string, tag="4")]
    pub btc_pk_hex: ::prost::alloc::string::String,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="5")]
    pub pop: ::core::option::Option<ProofOfPossessionBtc>,
    /// consumer_id is the ID of the consumer the finality provider is operating on.
    /// If it's missing / empty, it's assumed the finality provider is operating in Babylon.
    #[prost(string, tag="8")]
    pub consumer_id: ::prost::alloc::string::String,
}
/// ActiveBTCDelegation is an IBC packet sent from Babylon to consumer
/// upon a BTC delegation newly receives covenant signatures and thus becomes active
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActiveBtcDelegation {
    /// staker_addr is the address to receive rewards from BTC delegation.
    #[prost(string, tag="11")]
    pub staker_addr: ::prost::alloc::string::String,
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
/// SlashedBTCDelegation is an IBC packet sent from Babylon to consumer
/// about a slashed BTC delegation restaked to >=1 of this consumer's 
/// finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SlashedBtcDelegation {
    /// staking tx hash of the BTC delegation. It uniquely identifies a BTC delegation
    #[prost(string, tag="1")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// recovered_fp_btc_sk is the extracted BTC SK of the finality provider on
    /// this consumer
    /// this allows the consumer to verify the BTC delegation is indeed slashed
    #[prost(string, tag="2")]
    pub recovered_fp_btc_sk: ::prost::alloc::string::String,
}
/// UnbondedBTCDelegation is an IBC packet sent from Babylon to consumer
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
