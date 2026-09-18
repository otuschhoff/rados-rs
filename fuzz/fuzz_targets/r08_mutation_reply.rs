#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| rados::r08_integration::fuzz_mutation_reply(data));
