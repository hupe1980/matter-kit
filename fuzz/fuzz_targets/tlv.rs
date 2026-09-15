//! Does any byte string make the TLV reader panic?
//!
//! It must not. The reader is the first thing that touches a payload from the network, and
//! `unwrap`, `expect`, `panic!` and slice indexing are denied in its module precisely so
//! that this target has something to prove. An error is a pass; a panic is a bug and, on a
//! device, a denial of service that any peer on the LAN can trigger.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::tlv::{Pretty, TlvReader, validate_canonical};

fuzz_target!(|data: &[u8]| {
    let _ = TlvReader::validate(data);
    let _ = validate_canonical(data);

    // The pretty printer promises to print what it understood rather than fail, so it must
    // survive the same inputs.
    use core::fmt::Write as _;
    let mut sink = Sink;
    let _ = write!(sink, "{}", Pretty(data));

    // Element-by-element, including skipping containers — a different path through the
    // reader than `validate` takes.
    let mut r = TlvReader::new(data);
    while let Ok(Some(element)) = r.next_element() {
        if element.value.container().is_some() {
            if r.skip_container().is_err() {
                break;
            }
        }
    }
});

/// Formats without keeping the output: the question is whether it panics, not what it says.
struct Sink;

impl core::fmt::Write for Sink {
    fn write_str(&mut self, _: &str) -> core::fmt::Result {
        Ok(())
    }
}
