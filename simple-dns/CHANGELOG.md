# 0.5.1 (2023-01-17)

### Fixed
- Prevent panic! when trying to parse an empty slice

# 0.5.0 (2022-12-10)

### Fixed
- Fixes parsing for Name, CharacterString and SOA types 

### Changed (Breaking)
- Header flags now use crate [bitflags](https://crates.io/crates/bitflags)
- Removed PacketBuf struct, due to how EDNS0 packets are constructed.  
It is necessary to parse the whole packet to be able to construct the header information, which renders the PacketBuf *on the fly* approach unreliable

### Added
- Add OPT record type from RFC 6891 (EDNS0 support)
- header_buffer module for packet header manipulation
- tests using sample files from bind9


# 0.4.7

- Remove `thiserror` dependency
- Add RFC 2136
- Add RFC 1183
- Add RFC 1706
- Add RFC 1876
- Add NOTIFY code (RFC 1995 and 1996)
- Add new error type `InsufficientData` for stream parsing

# 0.4.6
- Add cache flush bit parsing to resource records

# 0.4.5
- Fix TXT records length

# 0.4.4
-Fix PTR parsing with compression

# 0.4.3
- Improve error handling

# 0.4.2
- Fix Name compression when using multiple pointers

# 0.4.1
- Fix a panic when parsing TXT records of length 0

# 0.4.0
- Change internal data references to use Cow
- Add **into_owned** function to every resource
- Add **is_subdomain_of** for Name comparison
- Change RData::SRV to not use a Box anymore 

# 0.3.0
- Fix TXT Resource Record implementation
- Drop byteorder crate dependency

# 0.2.1
- Fix Name hash function
- Fix SRV compression

# 0.2.0

- Add Name compression
- Change DnsPacketContent visibility to pub(crate)
- Rename PacketSectionIter to QuestionsIter 

# 0.1.0

Initial project release
