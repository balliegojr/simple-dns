#![no_main]

use libfuzzer_sys::fuzz_target;

use simple_dns::Packet;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    if let Ok(original) = Packet::parse(data) {
        let compressed = original.build_bytes_vec_compressed().unwrap();

        match Packet::parse(&compressed) {
            Ok(decompressed) => {
                let encoded = decompressed.build_bytes_vec().unwrap();

                assert_eq!(encoded, original.build_bytes_vec().unwrap());
            }
            Err(e) => {
                eprintln!("{:?}", original);
                panic!("Packet failed to parse: {:?}", e);
            }
        }
    }
});
