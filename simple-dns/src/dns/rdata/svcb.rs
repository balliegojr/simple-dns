use std::{borrow::Cow, convert::TryInto};

use crate::dns::{PacketPart, MAX_SVC_PARAM_VALUE_LENGTH};
use crate::{CharacterString, Name};

use super::RR;

/// The SVCB DNS RR type is used to locate alternative endpoints for a service.
/// [RFC 9460](https://datatracker.ietf.org/doc/html/rfc9460).
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SVCB<'a> {
    /// The priority of this record (relative to others, with lower values preferred).
    ///
    /// A value of 0 indicates AliasMode.
    pub priority: u16,

    /// The domain name of either the alias target (for AliasMode)
    /// or the alternative endpoint (for ServiceMode).
    pub target: Name<'a>,

    /// A list of key=value pairs describing the alternative endpoint at `target`.
    pub params: Vec<SvcParam<'a>>,
}

/// Parameters of a [`SVCB`] or [`HTTPS`](super::HTTPS) record.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SvcParam<'a> {
    /// The SvcParamKey.
    pub key: u16,
    value: Cow<'a, [u8]>,
}

impl<'a> SvcParam<'a> {
    /// Mandatory keys in this RR.
    pub const MANDATORY: u16 = 0;

    /// Additional supported protocols.
    pub const ALPN: u16 = 1;

    /// No support for default protocol.
    pub const NO_DEFAULT_ALPN: u16 = 2;

    /// Port for alternative endpoint.
    pub const PORT: u16 = 3;

    /// IPv4 address hints.
    pub const IPV4HINT: u16 = 4;

    /// Encrypted ClientHello (ECH) configuration.
    pub const ECH: u16 = 5;

    /// IPv6 address hints.
    pub const IPV6HINT: u16 = 6;

    fn internal_new(key: u16, value: Cow<'a, [u8]>) -> crate::Result<Self> {
        if value.len() > MAX_SVC_PARAM_VALUE_LENGTH {
            return Err(crate::SimpleDnsError::InvalidDnsPacket);
        }
        Ok(Self { key, value })
    }

    /// Creates a new arbitrary key=value pair.
    ///
    /// The format of `value` is not checked against the `key`.
    pub fn new(key: u16, value: &'a [u8]) -> crate::Result<Self> {
        Self::internal_new(key, Cow::Borrowed(value))
    }

    /// Creates a "mandatory" parameter.
    ///
    /// The list of keys MUST be listed in strictly increasing order.
    pub fn mandatory<I: IntoIterator<Item = u16>>(keys: I) -> crate::Result<Self> {
        let value = keys.into_iter().map(u16::to_be_bytes).flatten().collect();
        Self::internal_new(Self::MANDATORY, Cow::Owned(value))
    }

    /// Creates an "alpn" parameter.
    pub fn alpn<'cs, I: IntoIterator<Item = CharacterString<'cs>>>(
        alpn_ids: I,
    ) -> crate::Result<Self> {
        let mut value = Vec::new();
        for alpn_id in alpn_ids {
            alpn_id.write_to(&mut value)?;
        }
        Self::internal_new(Self::ALPN, Cow::Owned(value))
    }

    /// Creates a "no-default-alpn" parameter.
    pub const fn no_default_alpn() -> Self {
        Self {
            key: Self::NO_DEFAULT_ALPN,
            value: Cow::Borrowed(b""),
        }
    }

    /// Creates a "port" parameter.
    pub fn port(port: u16) -> Self {
        Self {
            key: Self::PORT,
            value: Cow::Owned(port.to_be_bytes().to_vec()),
        }
    }

    /// Creates an "ipv4hint" parameter.
    pub fn ipv4hint<I: IntoIterator<Item = u32>>(ips: I) -> crate::Result<Self> {
        let value = ips.into_iter().map(u32::to_be_bytes).flatten().collect();
        Self::internal_new(Self::IPV4HINT, Cow::Owned(value))
    }

    /// Creates an "ipv6hint" parameter.
    pub fn ipv6hint<I: IntoIterator<Item = u128>>(ips: I) -> crate::Result<Self> {
        let value = ips.into_iter().map(u128::to_be_bytes).flatten().collect();
        Self::internal_new(Self::IPV6HINT, Cow::Owned(value))
    }

    /// Gets a read-only reference to the SvcParamValue in wire format.
    // TODO actually parse the SvcParamValue?
    pub fn value(&'_ self) -> &'_ [u8] {
        &self.value
    }

    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> SvcParam<'b> {
        SvcParam {
            key: self.key,
            value: self.value.into_owned().into(),
        }
    }
}

impl<'a> RR for SVCB<'a> {
    const TYPE_CODE: u16 = 64;
}

impl<'a> SVCB<'a> {
    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> SVCB<'b> {
        SVCB {
            priority: self.priority,
            target: self.target.into_owned(),
            params: self.params.into_iter().map(SvcParam::into_owned).collect(),
        }
    }
}

impl<'a> PacketPart<'a> for SVCB<'a> {
    fn parse(data: &'a [u8], mut position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let priority = u16::from_be_bytes(data[position..position + 2].try_into()?);
        let target = Name::parse(data, position + 2)?;
        position += 2 + target.len();
        let mut params = Vec::new();
        while position < data.len() {
            let key = u16::from_be_bytes(data[position..position + 2].try_into()?);
            let value_length = usize::from(u16::from_be_bytes(
                data[position + 2..position + 4].try_into()?,
            ));
            params.push(SvcParam {
                key,
                value: Cow::Borrowed(&data[position + 4..position + 4 + value_length]),
            });
            position += 4 + value_length;
        }
        Ok(Self {
            priority,
            target,
            params,
        })
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&self.priority.to_be_bytes())?;
        self.target.write_to(out)?;
        for param in &self.params {
            out.write_all(&param.key.to_be_bytes())?;
            let value_length = param.value.len() as u16;
            out.write_all(&value_length.to_be_bytes())?;
            out.write_all(&param.value)?;
        }
        Ok(())
    }

    // NOT implementing `write_compressed_to`,
    // RFC9460 §2.2 specifically mentioned the TargetName is *uncompressed*.

    fn len(&self) -> usize {
        2 + self.target.len()
            + self
                .params
                .iter()
                .map(|param| param.value.len() + 4)
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rdata::RData, ResourceRecord};

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        // Copy of the answer from `dig crypto.cloudflare.com -t HTTPS`.
        let sample_file = std::fs::read("samples/zonefile/HTTPS.sample")?;

        let sample_rdata = match ResourceRecord::parse(&sample_file, 0)?.rdata {
            RData::HTTPS(rdata) => rdata,
            _ => unreachable!(),
        };

        assert_eq!(sample_rdata.priority, 1);
        assert_eq!(sample_rdata.target, Name::new_unchecked(""));
        assert_eq!(
            sample_rdata.params,
            vec![
                SvcParam::alpn(["http/1.1".try_into()?, "h2".try_into()?])?,
                SvcParam::ipv4hint([0xa2_9f_89_55, 0xa2_9f_8a_55])?,
                SvcParam::new(
                    SvcParam::ECH,
                    b"\x00\x45\
                        \xfe\x0d\x00\x41\x44\x00\x20\x00\x20\x1a\xd1\x4d\x5c\xa9\x52\xda\
                        \x88\x18\xae\xaf\xd7\xc6\xc8\x7d\x47\xb4\xb3\x45\x7f\x8e\x58\xbc\
                        \x87\xb8\x95\xfc\xb3\xde\x1b\x34\x33\x00\x04\x00\x01\x00\x01\x00\
                        \x12cloudflare-ech.com\x00\x00"
                )?,
                SvcParam::ipv6hint([
                    0x2606_4700_0007_0000_0000_0000_a29f_8955,
                    0x2606_4700_0007_0000_0000_0000_a29f_8a55
                ])?,
            ]
        );

        Ok(())
    }

    #[test]
    fn parse_and_write_svcb() {
        // Test vectors are taken from Appendix D.
        // <https://www.rfc-editor.org/rfc/rfc9460.html#name-test-vectors>
        let tests: &[(&str, &[u8], SVCB<'_>)] = &[
            (
                "D.1. AliasMode",
                b"\x00\x00\x03foo\x07example\x03com\x00",
                SVCB {
                    priority: 0,
                    target: Name::new_unchecked("foo.example.com"),
                    params: vec![],
                },
            ),
            (
                "D.2.3. TargetName Is '.'",
                b"\x00\x01\x00",
                SVCB {
                    priority: 1,
                    target: Name::new_unchecked(""),
                    params: vec![],
                },
            ),
            (
                "D.2.4. Specified a Port",
                b"\x00\x10\x03foo\x07example\x03com\x00\x00\x03\x00\x02\x00\x35",
                SVCB {
                    priority: 16,
                    target: Name::new_unchecked("foo.example.com"),
                    params: vec![
                        SvcParam::port(53),
                    ],
                },
            ),
            (
                "D.2.6. A Generic Key and Quoted Value with a Decimal Escape",
                b"\x00\x01\x03foo\x07example\x03com\x00\x02\x9b\x00\x09hello\xd2qoo",
                SVCB {
                    priority: 1,
                    target: Name::new_unchecked("foo.example.com"),
                    params: vec![
                        SvcParam::new(667, b"hello\xd2qoo").unwrap(),
                    ],
                },
            ),
            (
                "D.2.7. Two Quoted IPv6 Hints",
                b"\x00\x01\x03foo\x07example\x03com\x00\x00\x06\x00\x20\
                    \x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\
                    \x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x53\x00\x01",
                SVCB {
                    priority: 1,
                    target: Name::new_unchecked("foo.example.com"),
                    params: vec![
                        SvcParam::ipv6hint([
                            0x2001_0db8_0000_0000_0000_0000_0000_0001,
                            0x2001_0db8_0000_0000_0000_0000_0053_0001,
                        ]).unwrap(),
                    ],
                },
            ),
            (
                "D.2.10. SvcParamKey Ordering Is Arbitrary in Presentation Format but Sorted in Wire Format",
                b"\x00\x10\x03foo\x07example\x03org\x00\
                    \x00\x00\x00\x04\x00\x01\x00\x04\
                    \x00\x01\x00\x09\x02h2\x05h3-19\
                    \x00\x04\x00\x04\xc0\x00\x02\x01",
                SVCB {
                    priority: 16,
                    target: Name::new_unchecked("foo.example.org"),
                    params: vec![
                        SvcParam::mandatory([SvcParam::ALPN, SvcParam::IPV4HINT]).unwrap(),
                        SvcParam::alpn(["h2".try_into().unwrap(), "h3-19".try_into().unwrap()]).unwrap(),
                        SvcParam::ipv4hint([0xc0_00_02_01]).unwrap(),
                    ],
                },
            ),
        ];

        for (name, expected_bytes, svcb) in tests {
            let mut data = Vec::new();
            svcb.write_to(&mut data).unwrap();
            assert_eq!(expected_bytes, &data, "Test {name}");

            let svcb2 = SVCB::parse(&data, 0).unwrap();
            assert_eq!(svcb, &svcb2, "Test {name}");
        }
    }
}
