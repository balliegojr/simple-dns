# Simple DNS
Pure Rust implementation to work with DNS packets

You can parse or write a DNS packet by using [Packet](`Packet`) or [PacketBuf](`PacketBuf`) structs

## Packet
Packet holds references for the original data and it is more suitable for situations where
you need to manipulate the packet before generating the final bytes buffer

```rust
use simple_dns::*;
use simple_dns::rdata::*;
let question = Question::new(Name::new_unchecked("_srv._udp.local"), QTYPE::TXT, QCLASS::IN, false);
let resource = ResourceRecord::new(Name::new_unchecked("_srv._udp.local"), CLASS::IN, 10, RData::A(A { address: 10 }));

let mut packet = Packet::new_query(1, false);
packet.questions.push(question);
packet.additional_records.push(resource);

let bytes = packet.build_bytes_vec();
assert!(bytes.is_ok());

// Same as above, but Names are compressed
let bytes = packet.build_bytes_vec_compressed();
assert!(bytes.is_ok());
```
It doesn't matter what order the resources are added, the packet will be built only when `build_bytes_vec` is called

To parse the contents of a buffer into a packet, you need call call [Packet::parse]
```rust
use simple_dns::Packet;

let bytes = b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
let packet = Packet::parse(&bytes[..]);
assert!(packet.is_ok());
```

## PacketBuf
PacketBuf holds an internal buffer that is populated right when a resource is added.  
It DOES matter the order in which the resources are added

```rust
use simple_dns::*;
use simple_dns::rdata::*;
let question = Question::new(Name::new_unchecked("_srv._udp.local"), QTYPE::TXT, QCLASS::IN, false);
let resource = ResourceRecord::new(Name::new_unchecked("_srv._udp.local"), CLASS::IN, 10, RData::A(A { address: 10 }));

let mut packet = PacketBuf::new(PacketHeader::new_query(1, false), true);
assert!(packet.add_answer(&resource).is_ok());
assert!(packet.add_question(&question).is_err()); //This will fail, since an answer is already added
```

It is possible to create a [PacketBuf](`PacketBuf`) from a buffer by calling [PacketBuf::from](`PacketBuf::from`), but be aware that this will clone the contents from the buffer

## DNS Packet Parser/Builder
The *Packet* structure provides parsing e building of a DNS packet, it aims to be fully compliant with the RFCs bellow:
- [RFC 1034](https://tools.ietf.org/html/rfc1034)
- [RFC 1035](https://tools.ietf.org/html/rfc1035)
- [RFC 1138](https://tools.ietf.org/html/rfc1138)
- [RFC 6762](https://tools.ietf.org/html/rfc6762)
- [RFC 2782](https://tools.ietf.org/html/rfc2782)
- [RFC 3596](https://tools.ietf.org/html/rfc3596)

Other Resource Records defined by other RFCs that are not in this list will be implemented over time

