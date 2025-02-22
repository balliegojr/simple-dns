use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use base64::prelude::*;
use simple_dns::rdata::*;
use simple_dns::CharacterString;
use simple_dns::Name;
use simple_dns::CLASS;

macro_rules! check_bind9 {
    ( $ty:ident, $rdata:expr, $text:expr) => {
        check_bind9!($ty, $rdata, $text, $text);
    };
    ($ty:ident, $rdata:expr, $text:expr, $text_comp:expr) => {
        let type_code = simple_dns::testing::type_code::<$ty>();
        let bytes = crate::text_to_wire($text, CLASS::IN as u16, type_code);
        let parsed = simple_dns::testing::parse::<$ty>(&bytes);
        assert_eq!($rdata, parsed, "parsed data differ");

        let parsed_bytes = simple_dns::testing::get_bytes(parsed);

        let text_rpr = crate::wire_to_text(&parsed_bytes, CLASS::IN as u16, type_code);
        assert_eq!(*$text_comp, text_rpr, "text representation differ");
    };
}

#[test]
fn a_bind9_compatible() {
    let text = "127.0.0.1";
    let rdata = A {
        address: std::net::Ipv4Addr::new(127, 0, 0, 1).into(),
    };

    check_bind9!(A, rdata, &text);
}

#[test]
fn aaaa_bind9_compatible() {
    let text = "fd92:7065:b8e:ffff::5";
    let rdata = AAAA {
        address: text.parse::<Ipv6Addr>().unwrap().into(),
    };

    check_bind9!(AAAA, rdata, text);
}

#[test]
fn afsdb_bind9_compatible() {
    let text = "1 afsdb.hostname.com.";
    let rdata = AFSDB {
        subtype: 1,
        hostname: Name::new("afsdb.hostname.com").unwrap(),
    };

    check_bind9!(AFSDB, rdata, &text);
}

#[test]
fn caa_bind9_compatible() {
    let text = r#"0 issue "ca1.example.net""#;
    let rdata = CAA {
        flag: 0,
        tag: CharacterString::new(b"issue").unwrap(),
        value: b"ca1.example.net".into(),
    };

    check_bind9!(CAA, rdata, text);
}

#[test]
fn cert_bind9_compatible() {
    let text = "65534 65535 PRIVATEOID MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDq5a0oiMxJ iOdwaSmkU2NPPJXOWPZVWpIGxB0kczGcCS6Xq0VinNqLe5YI9M1YwXeh ZANiAASeQ9fMKeGOSzWhj7ePMA9Ws1t/wGKbIyFwsSvnc/nqOAFmS1JD Mc8QaRW/awjzaQc/mbu4cNA7iSId8iVCWj5VkcP8tL7HLYZRFMSr/nxU NGfHXtuGhMxm61SvnX3czhg=";
    let rdata = CERT {
            type_code: 65534,
            key_tag: 65535,
            algorithm: 254,
            certificate: Cow::Owned(BASE64_STANDARD.decode("MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDq5a0oiMxJiOdwaSmkU2NPPJXOWPZVWpIGxB0kczGcCS6Xq0VinNqLe5YI9M1YwXehZANiAASeQ9fMKeGOSzWhj7ePMA9Ws1t/wGKbIyFwsSvnc/nqOAFmS1JDMc8QaRW/awjzaQc/mbu4cNA7iSId8iVCWj5VkcP8tL7HLYZRFMSr/nxUNGfHXtuGhMxm61SvnX3czhg=").unwrap()),
        };

    check_bind9!(CERT, rdata, text);
}

#[test]
fn dhcid_bind9_compatible() {
    let text = r"AAABxLmlskllE0MVjd57zHcWmEH3pCQ6VytcKD//7es/deY=";
    let rdata = DHCID {
        identifier: 0,
        digest_type: 1,
        digest: Cow::Borrowed(&[
            196, 185, 165, 178, 73, 101, 19, 67, 21, 141, 222, 123, 204, 119, 22, 152, 65, 247,
            164, 36, 58, 87, 43, 92, 40, 63, 255, 237, 235, 63, 117, 230,
        ]),
    };

    check_bind9!(DHCID, rdata, text);
}

#[test]
fn dnskey_bind9_compatible() {
    let text = "512 255 1 AQMFD5raczCJHViKtLYhWGz8hMY9UGRuniJDBzC7w0aRyzWZriO6i2od GWWQVucZqKVsENW91IOW4vqudngPZsY3GvQ/xVA8/7pyFj6b7Esga60z yGW6LFe9r8n6paHrlG5ojqf0BaqHT+8=";
    let rdata = DNSKEY {
        flags: 512,
        protocol: 255,
        algorithm: 1,
        public_key: Cow::Owned(BASE64_STANDARD.decode("AQMFD5raczCJHViKtLYhWGz8hMY9UGRuniJDBzC7w0aRyzWZriO6i2odGWWQVucZqKVsENW91IOW4vqudngPZsY3GvQ/xVA8/7pyFj6b7Esga60zyGW6LFe9r8n6paHrlG5ojqf0BaqHT+8=").unwrap()),
    };
    check_bind9!(DNSKEY, rdata, text);
}

#[test]
fn hinfo_bind9_compatible() {
    let text = r#""Generic PC clone" "NetBSD-1.4""#;
    let rdata = HINFO {
        cpu: "Generic PC clone".try_into().unwrap(),
        os: "NetBSD-1.4".try_into().unwrap(),
    };

    check_bind9!(HINFO, rdata, &text);
}

#[test]
fn ds_bind9_compatible() {
    let text = "12892 5 1 7AA4A3F416C2F2391FB7AB0D434F762CD62D1390";
    let rdata = DS {
        key_tag: 12892,
        algorithm: 5,
        digest_type: 1,
        digest: Cow::Borrowed(&[
            0x7A, 0xA4, 0xA3, 0xF4, 0x16, 0xC2, 0xF2, 0x39, 0x1F, 0xB7, 0xAB, 0x0D, 0x43, 0x4F,
            0x76, 0x2C, 0xD6, 0x2D, 0x13, 0x90,
        ]),
    };
    check_bind9!(DS, rdata, &text);
}

#[test]
fn eui48_bind9_compatible() {
    let text = "01-23-45-67-89-ab";
    let rdata = EUI48 {
        address: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab],
    };
    check_bind9!(EUI48, rdata, &text);
}

#[test]
fn eui64_bind9_compatible() {
    let text = "01-23-45-67-89-ab-cd-ef";
    let rdata = EUI64 {
        address: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
    };
    check_bind9!(EUI64, rdata, &text);
}

#[test]
fn _ipseckey_bind9_compatible() {
    let text = "10 3 2 mygateway.example.com. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==";
    let rdata = IPSECKEY {
        precedence: 10,
        algorithm: 2,
        gateway: Gateway::Domain(Name::new_unchecked("mygateway.example.com")),
        public_key: Cow::Owned(
            BASE64_STANDARD
                .decode("AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==")
                .unwrap(),
        ),
    };

    check_bind9!(IPSECKEY, rdata, &text);
}

#[test]
fn isdn_bind9_compatible() {
    let text = r#""isdn-address" "subaddress""#;
    let rdata = ISDN {
        address: "isdn-address".try_into().unwrap(),
        sa: "subaddress".try_into().unwrap(),
    };
    check_bind9!(ISDN, rdata, &text);
}

#[test]
fn kx_bind9_compatible() {
    let text = "10 kdc.";
    let rdata = KX {
        preference: 10,
        exchanger: "kdc".try_into().unwrap(),
    };
    check_bind9!(KX, rdata, &text);
}

#[test]
fn loc_bind9_compatible() {
    let text = "60 9 0.000 N 24 39 0.000 E 10.05m 20m 2000m 20m";
    let rdata = LOC {
        version: 0,
        size: 35,
        vertical_precision: 35,
        horizontal_precision: 37,
        altitude: 10001005,
        longitude: -2058743648,
        latitude: -1930943648,
    };
    check_bind9!(LOC, rdata, &text);
}

#[test]
fn minfo_bind9_compatible() {
    let text = "rmailbx. emailbx.";
    let rdata = MINFO {
        rmailbox: Name::new_unchecked("rmailbx"),
        emailbox: Name::new_unchecked("emailbx"),
    };
    check_bind9!(MINFO, rdata, &text);
}

#[test]
fn mx_bind9_compatible() {
    let text = "10 exchange.";
    let rdata = MX {
        preference: 10,
        exchange: Name::new_unchecked("exchange"),
    };
    check_bind9!(MX, rdata, &text);
}

#[test]
fn naptr_bind9_compatible() {
    let text = r#"65535 65535 "blurgh" "blorf" "blllbb" foo."#;
    let rdata = NAPTR {
        order: 65535,
        preference: 65535,
        flags: CharacterString::new(b"blurgh").unwrap(),
        services: CharacterString::new(b"blorf").unwrap(),
        regexp: CharacterString::new(b"blllbb").unwrap(),
        replacement: Name::new_unchecked("foo"),
    };

    check_bind9!(NAPTR, rdata, &text);
}

#[test]
fn nsap_bind9_compatible() {
    let text = "0x47.0005.80.005a00.0010.1000.e133.ffffff000164.10";
    let nsap = NSAP {
        afi: 0x47,
        idi: 5,
        dfi: 0x80,
        aa: 0x005a00,
        rsvd: 0x10,
        rd: 0x1000,
        area: 0xe133,
        id: 0xffffff000164,
        sel: 0x10,
    };

    check_bind9!(NSAP, nsap, &text, text.replace(".", ""));
}

#[test]
fn nsec_bind9_compatible() {
    let text = "host.example.com. A MX RRSIG NSEC TYPE1234";
    let rdata = NSEC {
        next_name: Name::new_unchecked("host.example.com"),
        type_bit_maps: vec![
            NsecTypeBitMap {
                window_block: 0,
                bitmap: (&[0x40, 0x01, 0x00, 0x00, 0x00, 0x03]).into(),
            },
            NsecTypeBitMap {
                window_block: 4,
                bitmap: (&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x20,
                ])
                    .into(),
            },
        ],
    };
    check_bind9!(NSEC, rdata, &text);
}

#[test]
fn route_through_bind9_compatible() {
    let text = "10 intermediate-host.sample.";
    let rdata = RouteThrough {
        preference: 10,
        intermediate_host: Name::new_unchecked("intermediate-host.sample"),
    };
    check_bind9!(RouteThrough, rdata, &text);
}

#[test]
fn rp_bind9_compatible() {
    let text = "mbox-dname.sample. txt-dname.sample.";
    let rdata = RP {
        mbox: "mbox-dname.sample".try_into().unwrap(),
        txt: "txt-dname.sample".try_into().unwrap(),
    };

    check_bind9!(RP, rdata, text);
}

#[test]
fn rrsig_bind9_compatible() {
    let text = "NSEC 1 3 3600 20000102030405 19961211100908 2143 foo.nil. MxFcby9k/yvedMfQgKzhH5er0Mu/vILz45IkskceFGgiWCn/GxHhai6V AuHAoNUz4YoU1tVfSCSqQYn6//11U6Nld80jEeC8aTrO+KKmCaY=";

    let rdata = RRSIG {
        type_covered: 47,
        algorithm: 1,
        labels: 3,
        original_ttl: 3600,
        signature_expiration: 946782245,
        signature_inception: 850298948,
        key_tag: 2143,
        signer_name: Name::new_unchecked("foo.nil"),
        signature: BASE64_STANDARD.decode("MxFcby9k/yvedMfQgKzhH5er0Mu/vILz45IkskceFGgiWCn/GxHhai6VAuHAoNUz4YoU1tVfSCSqQYn6//11U6Nld80jEeC8aTrO+KKmCaY=").unwrap().into(),
                
    };

    check_bind9!(RRSIG, rdata, text);
}

#[test]
fn soa_bind9_compatible() {
    let text = "a.test. hostmaster.null. 1613723740 900 300 604800 900";
    let rdata = SOA {
        mname: Name::new_unchecked("a.test"),
        rname: Name::new_unchecked("hostmaster.null"),
        serial: 1613723740,
        refresh: 900,
        retry: 300,
        expire: 604800,
        minimum: 900,
    };

    check_bind9!(SOA, rdata, text);
}

#[test]
fn srv_bind9_compatible() {
    let text = "65535 65535 65535 old-slow-box.";
    let rdata = SRV {
        priority: 65535,
        weight: 65535,
        port: 65535,
        target: Name::new_unchecked("old-slow-box"),
    };

    check_bind9!(SRV, rdata, text);
}

#[test]
fn svcb_bind9_compatible() {
    let text = r#"3 svc4.example.net. alpn="bar" port=8004 ech=AAPTTTQ= key667="hello\210qoo""#;

    let rdata = SVCB::new(3, Name::new_unchecked("svc4.example.net"))
        .with_param(SVCParam::Alpn(vec!["bar".try_into().unwrap()]))
        .with_param(SVCParam::Port(8004))
        .with_param(SVCParam::Unknown(
            667,
            (&[0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xd2, 0x71, 0x6f, 0x6f]).into(),
        )).with_param(SVCParam::Ech((&[211, 77, 52]).into()));

    check_bind9!(SVCB, rdata, text);
}

#[test]
fn txt_bind9_compatible() {
    let text = r#""\"foo\010bar\"""#;
    let rdata: TXT = "\"foo\nbar\"".try_into().unwrap();

    check_bind9!(TXT, rdata, text);
}

#[test]
fn wks_bind9_compatible() {
    let text = "10.0.0.1 tcp telnet ftp 0 1 2";
    let rdata = WKS {
        address: Ipv4Addr::new(10, 0, 0, 1).into(),
        protocol: 6,
        bit_map: (&[224, 0, 5]).into(),
    };

    check_bind9!(WKS, rdata, text, "10.0.0.1 6 0 1 2 21 23");
}

#[test]
fn zonemd_bind9_compatible() {
    let text = "2019020700 1 0 C220B8A6ED5728A971902F7E3D4FD93ADEEA88B0453C2E8E8C863D46 5AB06CF34EB95B266398C98B59124FA239CB7EEB";
    let rdata = ZONEMD {
        serial: 2019020700,
        scheme: 1,
        algorithm: 0,
        digest: b"\xC2\x20\xB8\xA6\xED\x57\x28\xA9\x71\x90\x2F\x7E\x3D\x4F\xD9\x3A\xDE\xEA\x88\xB0\x45\x3C\x2E\x8E\x8C\x86\x3D\x46\x5A\xB0\x6C\xF3\x4E\xB9\x5B\x26\x63\x98\xC9\x8B\x59\x12\x4F\xA2\x39\xCB\x7E\xEB".into()
    };

    check_bind9!(ZONEMD, rdata, text);
}
