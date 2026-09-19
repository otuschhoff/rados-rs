#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| rados::r10_integration::fuzz_class(data));
