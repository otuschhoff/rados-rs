#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| rados::r07_integration::fuzz_osd_reply(data));
