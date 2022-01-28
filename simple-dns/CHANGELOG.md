# Simple DNS
## 0.4.2
- Fix Name compression when using multiple pointers

## 0.4.1
- Fix a panic when parsing TXT records of length 0

## 0.4.0
- Change internal data references to use Cow
- Add **into_owned** function to every resource
- Add **is_subdomain_of** for Name comparison
- Change RData::SRV to not use a Box anymore 

## 0.3.0
- Fix TXT Resource Record implementation
- Drop byteorder crate dependency

## 0.2.1
- Fix Name hash function
- Fix SRV compression

## 0.2.0

- Add Name compression
- Change DnsPacketContent visibility to pub(crate)
- Rename PacketSectionIter to QuestionsIter 

## 0.1.0

Initial project release
