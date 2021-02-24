pub mod dns;
pub mod mdns;

type Result<T> = std::result::Result<T, SimpleMdnsError>;

#[derive(Debug)]
pub enum SimpleMdnsError {
    InvalidClass(u16),
    InvalidQClass(u16),
    InvalidQType(u16),
    InvalidServiceName,
    InvalidServiceLabel,
    InvalidHeaderData,
    InvalidDnsPacket

}
