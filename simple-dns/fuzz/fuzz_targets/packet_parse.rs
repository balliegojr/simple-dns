#![no_main]

use libfuzzer_sys::fuzz_target;

use simple_dns::Packet;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    if let Ok(original) = Packet::parse(data) {
        let compressed = original.build_bytes_vec_compressed().unwrap();

        if let Ok(decompressed) = Packet::parse(&compressed) {
            let encoded = decompressed.build_bytes_vec().unwrap();

            assert_eq!(encoded, original.build_bytes_vec().unwrap());
        }
    }
});
