+++
title = "matter-kit"
description = "A Matter 1.6 protocol implementation in Rust: one crate, no_std, no allocation, and no runtime of its own. Sizing is a trait, not a build flag, and nothing panics on network input."
template = "index.html"

[extra]
tagline = "Matter is the CSA smart-home standard behind Apple Home, Google Home, Alexa and SmartThings. matter-kit implements specification 1.6 in a single Rust crate that runs on a 256 KB microcontroller and brings no runtime of its own."
status_note = "Under construction and pre-1.0. The CHIP SDK's own chip-tool commissions the example device end to end with attestation verified, and eleven of the CSA Test Harness's certification cases pass against it. A device can be commissioned over IPv6, Bluetooth LE, Wi-Fi PAF or NFC, answer Reads, Writes and Invokes, hold subscriptions, take part in groupcast, and move a firmware image over TCP. Most of the application clusters' behaviour is what is left."

[[extra.pillars]]
title = "One crate"
body = "Not a family to keep in version step. Everything optional is a Cargo feature, and the code generator is repository tooling rather than a dependency."

[[extra.pillars]]
title = "Sizing is a type"
body = "Every table is a fixed-capacity array whose length comes from a Config trait. The specification's minima are const assertions, so a node that could not pass certification does not compile."

[[extra.pillars]]
title = "No runtime is chosen for you"
body = "async over core::future, reaching the outside world through small traits: sockets, timers, randomness, storage. No executor crate appears anywhere in the tree — the examples run on a block_on of their own."

[[extra.pillars]]
title = "Nothing panics on network input"
body = "unwrap, expect, panic! and slice indexing are denied crate-wide. Resource exhaustion is a value, so a device that runs out of exchanges answers BUSY rather than aborting."
+++

```rust
use matter_kit::Config;

struct Light;
impl Config for Light {
    const FABRICS: usize = 5;      // Core §11.18.5.3 constrains this to 5..=254
    const SESSIONS: usize = 16;    // Core §4.14.2.8 wants ≥ 3 per fabric
    // …everything else defaults.
}
```

Cargo features cannot do this. They are global and additive, so two crates in one binary
that ask for different sizes silently get the union, and nothing checks the result against
the specification.
