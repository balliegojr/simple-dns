pub mod dns;
#[cfg(feature="mdns")]
pub mod mdns;

type Result<T> = std::result::Result<T, SimpleDnsError>;

#[derive(Debug)]
pub enum SimpleDnsError {
    InvalidClass(u16),
    InvalidQClass(u16),
    InvalidQType(u16),
    InvalidServiceName,
    InvalidServiceLabel,
    InvalidCharacterString,
    InvalidHeaderData,
    InvalidDnsPacket,
    ErrorSendingDNSPacket,
    ErrorReadingFromUDPSocket,
    ErrorCreatingUDPSocket

}
