+++
title = "matter-kit"
description = "A Matter 1.6 protocol implementation in Rust: one crate, no_std, no allocation, and no runtime of its own. A node that could not pass certification does not compile, and nothing panics on network input."
template = "index.html"

[extra]
tagline = "Matter is the CSA smart-home standard behind Apple Home, Google Home, Alexa and SmartThings. matter-kit implements specification 1.6 in a single Rust crate that links into 88 KiB of flash and 39 KiB of RAM on an nRF52840 and brings no runtime of its own."
status_note = "Under construction and pre-1.0. The CHIP SDK's own chip-tool commissions the example device end to end with attestation verified, and eleven of the CSA Test Harness's certification cases pass against it. A device can be commissioned over IPv6, Bluetooth LE, Wi-Fi PAF or NFC, answer Reads, Writes and Invokes, hold subscriptions, take part in groupcast, and move a firmware image over TCP. Most of the application clusters' behaviour is what is left."

[[extra.pillars]]
title = "One crate"
body = "Not a family to keep in version step. Everything optional is a Cargo feature, and the code generator is repository tooling rather than a dependency."

[[extra.pillars]]
title = "A capacity is checked against the specification"
body = "Every table is a fixed-capacity array, and each one asserts at compile time that it can keep the per-fabric promises the node advertises. A node that could not pass certification does not compile, and the build error names the rule it breaks."

[[extra.pillars]]
title = "No runtime is chosen for you"
body = "async over core::future, reaching the outside world through small traits: sockets, timers, randomness, storage. No executor crate appears anywhere in the tree — the examples run on a block_on of their own."

[[extra.pillars]]
title = "Nothing panics on network input"
body = "unwrap, expect, panic!, slice indexing, unchecked arithmetic and truncating casts are denied crate-wide. Resource exhaustion is a value, so a device that runs out of exchanges answers BUSY rather than aborting."
+++

```rust
use matter_kit::{DefaultConfig, acl::Acl};

// Four entries for each of five fabrics is §2.11.1.1's minimum, and the default.
let acl: Acl<DefaultConfig> = Acl::new();

// error: Acl: Core §2.11.1.1 promises ACL_ENTRIES_PER_FABRIC to every fabric,
//        so the list must hold FABRICS × that many
let too_small: Acl<DefaultConfig, 4, 4, 3> = Acl::new();
```

Cargo features cannot do this. They are global and additive, so two crates in one binary
that ask for different sizes silently get the union, and nothing checks the result against
the specification.
