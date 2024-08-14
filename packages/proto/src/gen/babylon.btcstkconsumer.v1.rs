// @generated
/// ConsumerRegisterPacketData defines the packet data for consumer registration
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsumerRegisterIbcPacket {
    #[prost(string, tag="1")]
    pub consumer_name: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub consumer_description: ::prost::alloc::string::String,
}
// @@protoc_insertion_point(module)
