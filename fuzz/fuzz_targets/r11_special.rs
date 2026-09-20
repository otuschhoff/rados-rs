#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| rados::r11_integration::fuzz_special(data));