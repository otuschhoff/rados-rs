#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| rados::r05_integration::fuzz_map_message(0, data));