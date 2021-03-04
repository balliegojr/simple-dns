# Simple DNS
This project provides DNS capabilities

## DNS Packet Parser/Builder
The *Packet* structure provides parsing e building of a DNS packet, it aims to be fully compliant with the RFCs bellow:
- [RFC 1034](https://tools.ietf.org/html/rfc1034)
- [RFC 1035](https://tools.ietf.org/html/rfc1035)
- [RFC 6762](https://tools.ietf.org/html/rfc6762)

Other Resource Records defined by other RFCs that are not in this list will be implemented over time

## Additional Features
### mDNS (TODO)
Provides mDNS service capabilities (Querier and advertiser only), aims to be fully compliant with [RFC 6762](https://tools.ietf.org/html/rfc6762)

```
Add how to use example
```

### DNS-SD (TODO)
Provides dns service discovery capabilities, aims to be fully compliant with [RFC 6763](https://tools.ietf.org/html/rfc6763)

```
Add how to use example
```

### DNSResponder (TODO)
Provides dns service responder

## Observations
mDNS and DNS-SD features depends on [tokio](https://github.com/tokio-rs/tokio) runtime