pub mod dns;
pub mod mdns;

type Result<T> = std::result::Result<T, SimpleDnsError>;

#[derive(Debug)]
pub enum SimpleDnsError {
    InvalidClass(u16),
    InvalidQClass(u16),
    InvalidQType(u16),
    InvalidServiceName,
    InvalidServiceLabel,
    InvalidHeaderData,
    InvalidDnsPacket

}
