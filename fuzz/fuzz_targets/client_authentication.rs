#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    portredirect::fuzz::client_authentication(data);
});
