#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::mem;

pub fn wire_to_text(data: &[u8], class: u16, type_: u16) -> String {
    let mut source_bytes = Vec::from(data);
    let mut intermediate_bytes = [0u8; 1024];
    let mut text_bytes = [0u8; 1024];

    unsafe {
        let mut rdata: dns_rdata_t = mem::zeroed();
        let mut source_buffer = buffer_init_and_set(&mut source_bytes);
        let mut intermediate_buffer = buffer_init(&mut intermediate_bytes);
        let mut text_buffer = buffer_init(&mut text_bytes);

        dns_rdata_init(&mut rdata);
        assert_eq!(
            0,
            dns_rdata_fromwire(
                &mut rdata,
                class,
                type_,
                &mut source_buffer,
                dns_decompress_DNS_DECOMPRESS_ALWAYS,
                &mut intermediate_buffer,
            ),
            "bind9 failed to parse wire data"
        );

        assert_eq!(
            0,
            dns_rdata_totext(&mut rdata, std::ptr::null(), &mut text_buffer)
        );

        String::from_utf8(text_bytes[..text_buffer.used as usize].to_vec())
            .expect("Failed to generate text representation")
    }
}

pub fn text_to_wire(data: &str, class: u16, type_: u16) -> Vec<u8> {
    let mut source_bytes = data.as_bytes().to_vec();
    assert!(source_bytes.len() < 1024);

    let mut intermediate_bytes = [0u8; 1024];
    let mut wire_bytes = [0u8; 1024];

    unsafe {
        let mut rdata: dns_rdata_t = mem::zeroed();
        let mut source_buffer = buffer_init_and_set(&mut source_bytes);
        let mut intermediate_buffer = buffer_init(&mut intermediate_bytes);
        let mut wire_buffer = buffer_init(&mut wire_bytes);

        let mut cctx: dns_compress_t = mem::zeroed();
        let mut mctx: *mut isc_mem_t = mem::zeroed();
        let mut lex: *mut isc_lex_t = mem::zeroed();
        let mut callbacks: dns_rdatacallbacks_t = mem::zeroed();

        isc__mem_create(&mut mctx);
        isc_lex_create(mctx, 64, &mut lex);
        assert_eq!(0, isc_lex_openbuffer(lex, &mut source_buffer));

        dns_rdata_init(&mut rdata);
        dns_rdatacallbacks_init(&mut callbacks);

        assert_eq!(
            0,
            dns_rdata_fromtext(
                &mut rdata,
                class,
                type_,
                lex,
                dns_rootname,
                0,
                mctx,
                &mut intermediate_buffer,
                &mut callbacks,
            )
        );

        dns_compress_init(&mut cctx, mctx, 0);

        assert_eq!(0, dns_rdata_towire(&mut rdata, &mut cctx, &mut wire_buffer));

        wire_bytes[..wire_buffer.used as usize].to_vec()
    }
}

unsafe fn buffer_init_and_set(data: &mut [u8]) -> isc_buffer_t {
    let mut buffer = buffer_init(data);

    buffer.used += data.len() as u32;
    buffer.active = buffer.used;

    buffer
}

unsafe fn buffer_init(buffer: &mut [u8]) -> isc_buffer_t {
    let mut b: isc_buffer_t = mem::zeroed();

    b.base = buffer.as_mut_ptr() as *mut std::ffi::c_void;
    b.length = buffer.len() as u32;
    b.magic = ISC_BUFFER_MAGIC;

    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_to_text() {
        let data = [0x7B, 0x00, 0x00, 0x01];
        let result = wire_to_text(&data, 1, 1);
        assert_eq!(result, "123.0.0.1");
    }

    #[test]
    fn test_text_to_wire() {
        let result = text_to_wire("123.0.0.1", 1, 1);
        assert_eq!([0x7B, 0x00, 0x00, 0x01], result[..]);
    }
}
