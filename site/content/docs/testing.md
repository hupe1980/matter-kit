+++
title = "Testing"
description = "A virtual clock instead of a real one, fuzzing at every parser, the specification's own published vectors, and mutation testing for the rules that have no vector."
weight = 14
+++

Half of Matter is deadlines: the reliability layer backs off over four seconds, a fail-safe
expires, an intermittently connected device sleeps for an hour, an mDNS name is claimed in
750 milliseconds. Testing that against a real clock means waiting, which means those paths
get tested rarely and flakily.

## Time is a parameter

`platform::sim` is a supported platform, not a test fixture: an in-process IPv6 network with
a virtual clock that jumps to the next deadline instead of waiting for it, plus loss,
duplication and jitter you set per test.

```rust
use matter_kit::platform::sim::{Impairment, SimNet, block_on};
use matter_kit::platform::{Timer, Duration};

let net = SimNet::new(42);              // seeded: same run, same result, every time
net.impair(Impairment::lossy(30));      // drop three datagrams in ten

let start = Timer::now(&net);
block_on(&net, async {
    net.sleep(Duration::from_secs(3600)).await;   // returns immediately
});
// An hour of virtual time has passed and no wall-clock time has.
assert_eq!(
    Timer::now(&net).saturating_duration_since(start),
    Duration::from_secs(3600)
);
```

The whole reliability layer runs through it: a lost message retransmitted until it lands, a
duplicate acknowledged but delivered once, a replay rejected by the counter window, a dead
peer abandoned after exactly five transmissions. Commissioning does too, including the cases
that matter most — a wrong passcode, a forged confirmation, and keys used in the wrong
direction.

## Published vectors, not self-consistency

Two implementations agreeing proves only that they share an opinion. Wherever the
specification prints a value, that value is the test: the TLV tables, the SPAKE2+ vectors,
the privacy nonce, the onboarding payload, the compressed fabric identifier, the operational
group key and IPK, the destination identifier, the RCAC/ICAC/NOC in both their Matter TLV
and X.509 forms, the Certification Declarations with their CMS wrappers, two DNS-SD record
listings, and the worked examples for network reordering and event encoding.

One check is stronger still, and was not designed. The first published Certification
Declaration and the published DAC chain come from different chapters, were written
independently, and happen to describe the same device. So the rules for relating a
declaration to a chain can be run on two documents that were never meant to be used
together — and they agree.

## Fuzzing

Twenty-six targets cover every parser that faces the network, and each asserts more than "no
panic": that iteration terminates, that borrowed payloads really are slices of the input,
that anything produced decodes again, and that a responder never answers a response.

They run for a minute on every pull request and for ten minutes nightly. The discovery target
is the one that matters most — it runs against code executing earliest in a device's life,
before commissioning and therefore before any Matter security exists at all.

`messaging` fuzzes the reception path — the code that runs first on anything arriving from
the network, and the only exposed parser with state worth attacking: a replay window, an
exchange table, MRP timers. It asserts that no datagram ever installs a session, that the
exchange table stays within its configured capacity, and that after any amount of garbage a
real exchange still opens and delivers.

Not every target is a parser. `acl` fuzzes the cluster that decides what every *other* cluster
will allow, where the failure mode is a quiet grant rather than a crash: it asserts that no
sequence of bytes ever creates an entry on a fabric other than the writer's, and that a PASE
entry — which §6.6.2.1 forbids — never enters the list.

`chunking` fuzzes a *liveness* property instead: it lets the
fuzzer choose the size and shape of every attribute value and the message budget, then checks
that splitting a report across messages terminates, that `MoreChunkedMessages` is set on
exactly the messages that are not the last, and that the chunks together carry each path
exactly once. The failure it exists to catch is not a crash — it is a device that promises a
continuation it never sends, or retries a value that will never fit.

## Mutation testing where there is no vector

Most of the specification is prose, and prose has no vector. For those rules the test is:
break the rule in the source, confirm a test fails, restore.

Every mutation that *survives* is a weak test, and each one found this way has been
strengthened — a test comparing a constant against itself, an iterator silently swallowing
decode errors, an encoder checked only against itself. A sample of what is pinned this way:

| Rule | Section | Breaking it |
|---|---|---|
| a concrete path gets a status, an expanded one is discarded | §8.4.3.2 | a wildcard read enumerates what a subject may not see |
| the first access check comes before the existence checks | §8.4.3.2 | the difference between two status codes is a map of the node |
| the cumulative fail-safe timer is never extended | §11.10.7.2 | an administrator holds a device hostage forever |
| the NOC's public key must match the device's own | §11.18.6.7 | an administrator impersonates the node it commissioned |
| the network list's order is precedence, and every operation preserves it | §11.9.7.10 | a device silently prefers a different access point |
| a lower event priority can never displace a higher one | §7.14.2 | a Debug flood loses the Critical record a safety application depends on |
| a name is not answered for until 250 ms after the third probe | RFC 6762 §8.1 | two devices both claim one name |
| a Timed window is consumed by the first request on it | §8.7.4 | one Timed Request pays for a second command, later |
| a disallowed element present is a defect, not a spare | §7.3 | a device advertises an attribute its feature map forbids |
| the `OffWaitTime` guard holds against a second `OnWithTimedOff` | §1.5.6.5 | the lights come back on behind the person who just left the room |
| a groupcast is acted on and never answered | §1.3.7.1.2 | one multicast to twenty lights draws twenty unicast replies at once |
| no fabric takes more than half the Scene Table | §1.4.6 | whoever commissions first fills the device; the second ecosystem gets nothing |
| removing a group removes its scenes | §1.3.7.4 | scenes accumulate for groups the endpoint has left, and nothing can reclaim them |
| a second `KeepActive` never shortens the first | §9.13.6.1 | one controller's request cancels most of another's |
| `ReachableChanged` fires on the change, not on the poll | §9.13.7.1 | a thirty-second poll pushes every other record out of the event ring |
| a device type's mandatory elements are demanded, not just its clusters | §9.2 | the app draws a scene button that does nothing |
| a Level Control command *without* On/Off does nothing while the light is off | §1.6.6.9 | a dimmer winds a switched-off lamp up, and turning it on blinds somebody |
| a 'with On/Off' command turns the light on before the fade, not after | §1.6.7.6 | the lamp snaps to full brightness instead of fading up |
| a slow `Move` accumulates tenths rather than rounding each tick | §1.6.7.2.2 | a rate of 1 rounds to zero every tick and never moves |
| a NOC's subject is the authority's to choose, not the device's | §11.18 | a device names itself, and can name itself as somebody else |
| the attestation and CSR nonces must come back unchanged | §11.18.6.1, §11.18.6.6 | a prior session's response is replayable |
| a good chain does not rescue a signature that did not verify | §6.2.3 | the chain is evidence about a key nothing proved possession of |
| the publisher chooses `MaxInterval`, and the subscriber uses it | §8.5.3.2 | a live subscription is torn down and rebuilt for ever |
| a subscriber allows a retransmission past `MaxInterval` | §8.5.4 | a working subscription dies on the first MRP retry |
| §4.5's length prefix does not count itself | §4.5.1 | two nodes agree until either talks to a third |
| a stream that lost its framing stays lost, and the connection closes | §4.15.2.3 | the prefix is the only message boundary there is, so everything after it is read as a header |
| MRP does not run on a TCP peer | §4.15 | the sender retransmits into a stream that had already delivered |
| BDX blocks arrive in ascending sequential counter order | §11.22.6.1 | a gap in a firmware image nobody notices until it is flashed |
| a definite-length transfer ends on exactly the length it promised | §11.22.6.5 | a truncated image is accepted as complete |
| a receiver-driven Sender waits for a query before sending | §11.22.6.2 | a sleepy node is woken by blocks it never asked for |
| an `AnnounceOTAProvider` never rewrites `DefaultOTAProviders` | §11.20.7.5 | any administrator on the fabric redirects every later update, including after its own access is removed |
| a TLS certificate an endpoint still names cannot be removed | §14.4.6.7 | the endpoint authenticates nothing, discovered at connection time |
| a fabric-scoped miss in chapter 14 is `NOT_FOUND`, never `UNSUPPORTED_ACCESS` | §14.4.6 | one administrator counts another's certificates and learns their ids |
| a Large Message command is refused on a transport that cannot carry one | §8.8.2.3, §14.4 | a 3000-octet certificate is attempted over UDP |
| every candidate key for a Group Session ID is tried, not just the first | §4.17.3.6 | one group's traffic is dropped whenever two keys collide |
| the group peer table is never recycled | §4.16.1 | an attacker evicts a peer and then replays that peer's traffic |
| an epoch key never comes back out of a `KeySetRead` | §11.2.7.2 | any administrator walks off with the key to every group message the node sends |
| the root endpoint is never in a group | §11.27.7.1 | a multicast reaches the clusters that manage the node itself |
| an NTL chain may not deliver more than it announced | §4.21.4.2 | the reassembly buffer fills on a length the sender chose — found by fuzzing |
| a recovery node waits 120 seconds before it advertises | §5.9.3 | the device broadcasts through every brief outage its access point has |
| an ICAC must answer *this* administrator's CSR | §11.25.6.3 | the anchor picks the key, and the joining ecosystem installs a CA it cannot sign with |
| a datastore group may not claim the Administrator or Anchor CAT | §11.24.7.4 | `0xFFFE` is inside the permitted range, so every member of the group gets the fabric |
| a thermostat with no clock has no current suggestion | §4.3.7 | the thermostat follows a window it can no longer tell it has left |

## Two transcriptions of one source

The cheapest useful test in the repository, and the one that found the most: every cluster
written by hand here was transcribed from the specification PDF, and every cluster in
[`clusters::generated`](@/docs/clusters.md) was produced by `cargo xtask` from the CSA's
machine-readable data model. The two were derived independently from the same source, so where
they disagree **one of them is wrong**.

`tests/conformance.rs` runs that comparison over every hand-written cluster. It is the only thing
that catches a `ClusterRevision` left a revision behind, an element list that does not move when
its feature map does, or a mistake in the validator itself — each of those is consistent with
every test written *for* the code that has it, which is the whole argument for keeping a second,
independent description of the same thing.

`tests/commissioner.rs` is the third instance and the largest: the commissioner was written from
§5.5 and the device's clusters from §11.18, and the test runs one against the other through the
whole flow. It found that `AddTrustedRootCertificate` has no response command — a commissioner
expecting one fails on every conformant device — and that a certificate authority must be told
whether it is a root or an intermediate, because §6.5.6.3 names them by different DN attributes
and the wrong one produces certificates that are individually valid and chain to nothing.

`tests/device_types.rs` does the same for device types. It is what holds a validator to the
*elements* a device type makes mandatory and not merely its clusters — an `On/Off Light` without
`TriggerEffect` and `CopyScene` is not one — and to counting client entries, without which a
light is indistinguishable from the switch that controls it.

A CI job regenerates the library from a fresh checkout of the data model and fails on any
difference, so the comparison stays honest as the specification moves.

## The gates

Every change runs: the suite under `std` and under `--no-default-features`; Clippy over every
target in both modes; rustdoc with warnings denied; builds for two bare-metal targets with
and without `defmt`; the full feature powerset; the minimum supported Rust version; a
regeneration of the cluster library, diffed; licence and advisory checks; and the fuzzers.

## Meeting other implementations

Everything above is `matter-kit` checking its own reading of the specification. Two things check
it against somebody else's, because a suite that only ever meets itself measures agreement rather
than correctness.

**`interop/`** depends on `rs-matter 0.3.0` and compares the two crates directly on the onboarding
payload (§5.1) and TLV (Appendix A) — over the published examples, over every boundary value, and
over arbitrary inputs with `proptest`. It is a separate workspace, so rs-matter's 217 crates never
enter `matter-kit`'s dependency graph, its feature powerset or its MSRV.

**`interop/chip/run.sh`** has `chip-tool` — the controller every certified Matter product is
paired by — commission `examples/light` through the whole of §5.5:

```text
ReadCommissioningInfo   ArmFailSafe        ConfigRegulatory      ConfigureTCAcknowledgments
SendPAICertificateRequest                  SendDACCertificateRequest
SendAttestationRequest  AttestationVerification                   AttestationRevocationCheck
SendOpCertSigningRequest                   ValidateCSR
GenerateNOCChain        SendTrustedRootCert                       SendNOC
EvictPreviousCaseSessions                  FindOperationalForStayActive
FindOperationalForCommissioningComplete    SendComplete
                                                   → Device commissioning completed with success
```

The last two lines are the ones that cost the most to reach. They are not credentials: they are
mDNS resolution of `_matter._tcp`, a CASE handshake on the identity just issued, and an
interaction-model command served over the operational session on a fabric that did not exist a
second earlier.

Attestation is **verified, not bypassed**: the device generates a §6.2.2 chain at start-up and
writes its PAA out, and `chip-tool` is pointed at that as its trust anchor, so the DAC chain, the
Certification Declaration and the NOCSR signature are all checked by somebody else's code.
`AddTrustedRootCertificate` and `AddNOC` both succeed — the crate accepts an operational identity
issued by the reference implementation.

**`interop/chip/python.sh`** runs the CSA Test Harness's own certification cases — the same
`TC_*.py` scripts an authorised test lab executes — out of the same image:

```sh
# All eleven pass.
./interop/chip/python.sh TC_CGEN_2_1 TC_OPCREDS_3_1 TC_ACL_2_2 TC_ACL_2_4 TC_ACL_2_6 \
    TC_ACL_2_10 TC_IDM_1_2 TC_IDM_1_4 TC_IDM_2_2 TC_IDM_2_3 TC_IDM_4_2
./interop/chip/python.sh --list   # all 603
```

A **skip** is reported as a skip and exits non-zero. Most `TC_*.py` carry a `has_attribute` or
`has_feature` decorator, so a device that does not implement the thing a case tests does not fail
it — the case declines to run, and Mobly's summary still reads `Failed 0`. The verdict is
therefore read whole: `Passed` equal to `Requested`, and `Skipped` zero.

`TC_OPCREDS_3_1` is the most searching of them by a long way: eighty-five steps that commission
a second and a third fabric through the Enhanced Commissioning Method, roll one back with
`ArmFailSafe(0)`, reconnect over PASE and read every credential list along the way.

A case is run with the arguments it declares for itself. Every `TC_*.py` carries an
`=== BEGIN CI TEST ARGUMENTS ===` header naming the `script-args` the SDK's own CI gives it, and
a large minority add a `--endpoint` or a PIXIT that the case refuses to run without. The runner
parses that header and passes it through, minus the flags it sets itself — and minus
`--enable-spec-errata-ci-only-disallowed-for-certification`, which relaxes a case in a way its
own name says is inadmissible.

Each case commissions the device itself over on-network discovery and opens a wildcard
subscription before its first assertion, so every run exercises mDNS, PASE, attestation, CASE
and the interaction model on a fabric that did not exist a moment earlier.

Both ends run in containers on an IPv6 Docker network, so it needs no radio, no second machine
and no C++ toolchain. It is the only gate here that has ever found a defect the others could
not, because every other gate has `matter-kit` on both ends — and two implementations of the
same misreading agree perfectly. Three patterns account for most of what it finds:

- **Correct for one of something, wrong for two.** One fabric, one subscriber, one report
  cursor. A fixture with one of a thing never exercises the code that has to tell two apart.
- **A library piece whose documented caller does not exist.** Every part built, tested, and
  joined to nothing. The symptom is silence, not an error.
- **A fixture that pins what production varies.** Three fixed key seeds hid a certificate serial
  number that was invalid for one key in 256.

The runner itself is held to the same standard, and has been wrong in the same ways — most
sharply by counting a *skipped* case as a pass, which is why the verdict is now read whole.
