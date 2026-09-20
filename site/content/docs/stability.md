+++
title = "Stability"
weight = 90
+++

What a dependency on `matter-kit` promises, what it does not, and how you find out before your
build does.

## Versions

The crate is `0.x`, so Cargo's rule applies: **`0.y` is the compatibility unit**. A change that
breaks source compatibility raises the minor — `0.3.0` — and a change that does not raises the
patch. `version = "0.2"` in your manifest therefore pins you to a line that will not break under
you; `version = "0.2.1"` does the same thing with a floor.

That is enforced rather than promised. `cargo-semver-checks` runs in CI on every push, compares
the public API against the version on crates.io, and fails when the manifest's version has not
been raised far enough for what changed.

It is the reason `0.3.0` is a minor bump rather than a patch. Run against `0.2.0` with a patch
version it reports eight failures by name — ten `Config` constants removed,
`CapabilityMinima::from_config` gone, `GroupKeys` and `IcdManagement` taking different
parameters, `dm::spec::Defect` becoming `#[non_exhaustive]`. The tool says so before the release
rather than a user discovering it after.

Until `1.0` the API will keep moving. `CHANGELOG.md` in the repository says what moved and what
to change; what follows is the policy behind it.

## The three surfaces you implement

Most of this crate is types you *call*, and a call site that stops compiling is a fifteen-minute
fix. Three surfaces are different, because you implement them and a change there is a change to
your code's shape:

| Surface | What it is | How it moves |
|---|---|---|
| `Config` | the sizes every table in the stack is built to | constants may be **added** with defaults in a patch release; removing one is a minor bump, and only happens when nothing reads it |
| `platform::{Timer, Clock, Rng, Udp, KvStore}` | the five traits that reach the outside world | new methods arrive with defaults where a default is meaningful; a required method is a minor bump |
| `crypto::KeyStore` | where private keys live | the same rule |

`ClusterHandler` sits just behind them: `read` is required, and everything else — `write`,
`invoke`, `data_version`, `on_lifecycle` — has a default, so a cluster you wrote against `0.3.0`
keeps compiling when the trait grows.

## Deprecation

Anything removed is deprecated first, in a released version, with `#[deprecated]` carrying the
replacement:

```rust,ignore
#[deprecated(since = "0.3.0", note = "use `Messaging::install_session`, which evicts (§4.11.1.1)")]
pub fn insert(&mut self, session: SecureSession) -> Result<()> { /* … */ }
```

It survives **at least one** minor release after that, so `0.3.0` deprecates and `0.4.0` may
remove. Two exceptions, both narrow and both stated rather than assumed:

- **A soundness or specification-conformance defect.** An API that cannot be used correctly is
  removed or changed as soon as the fix is known — `SessionTable::insert` answering `NoSpace`
  where §4.11.1.1 requires an eviction was not a thing to deprecate politely.
- **Anything nothing calls.** `cargo xtask api` reports the public functions with no caller and
  no test; those are removed without a deprecation cycle, because a deprecation warning nobody
  can see is ceremony.

## What is *not* stable, and is not meant to be

- **Wire behaviour is fixed by the specification, not by this crate.** Where the two disagree,
  the specification wins and the change ships in the next minor release, whatever it breaks.
  Interoperability is the product; API convenience is not.
- **`no_std` and no-allocation are invariants, not features.** They will not be relaxed.
- **Provisional Matter features** (behind `provisional`) follow Matter's own churn: the CSA may
  change them in a dot release, and so may this crate, in a patch.
- **Anything under `xtask/`, `interop/`, `fuzz/`, `footprint/` and `examples/`** is repository
  tooling. It is not published and carries no compatibility promise at all.

## Rust version

The MSRV is **1.88**, declared as `rust-version` and checked in CI. It follows *latest stable
minus two*, and raising it is a minor bump like any other break. The crate uses edition 2024.

## Features

Features are additive: enabling one never removes an item. The whole powerset is compiled on
every push — 192 combinations, four CI partitions — so a combination that does not build is a
bug, not a configuration you were supposed to avoid.

`default = ["rustcrypto"]`. A `no_std` device that brings its own cryptography uses
`default-features = false`.
