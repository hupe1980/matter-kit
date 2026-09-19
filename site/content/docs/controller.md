+++
title = "Controllers"
description = "Commissioning a device from this crate: the certificate authority, the §5.5 flow, and a client that watches what it commissioned."
weight = 7
+++

A controller is the other half of Matter. A device answers; a controller decides what to ask,
and before it can ask anything it has to put the device on a fabric — which means issuing it an
identity, checking the one it already has, and getting both onto the device inside a fail-safe
window.

Four pieces, and each is the counterpart of something on the device side:

| Controller | Device |
|---|---|
| `ca::CertAuthority` | `clusters::operational_credentials` |
| `commissioning::commissioner::Commissioner` | `clusters::general_commissioning` + the above |
| `im::client` | `im::server` + `im::subscription` |
| `attestation::factory` | the DAC a factory burned in |

They were written from §5.5, §6.5 and §11.18 separately from the device halves, which is what
makes `tests/commissioner.rs` worth having: it runs one against the other, and the places the
two readings disagree are the places a bug lives.

## The fabric's certificate authority

Every Matter fabric is rooted in one self-signed certificate, and §6.4.5.3 is blunt about what
its authority rests on:

> Trust in the Root CA is established by provenance, not by the self-signature.

So a root is trusted because a commissioner installed it. The CA's real work is the other two
certificates:

```rust,ignore
use matter_kit::ca::{CertAuthority, Identity, Validity};

let ca = CertAuthority::new(root_key, 0xCAFE).for_fabric(fabric_id);
let mut buf = [0u8; matter_kit::cert::CERT_TLV_MAX];
let root = ca.self_signed_root(&keys, &mut buf, Validity::years(now, 10))?;

let mut buf = [0u8; matter_kit::cert::CERT_TLV_MAX];
let noc = ca.issue_noc(&keys, &mut buf, &identity, &device_key, Validity::years(now, 1))?;
```

**The subject is the authority's to choose.** §11.18 gives the device's half: it generates a key
and signs a CSR. The CSR carries a public key and nothing else the CA is obliged to believe —
the commissioner decides the node id, the fabric id and the CATs. A CA that echoed a subject the
device proposed would let a device name itself, and a device that can name itself can name
itself as somebody else.

Nothing here takes a private key. `CertAuthority` holds a `KeyHandle` and signs through the
`KeyStore`, so a deployment with the fabric root in a secure element runs the same code as one
with it in RAM — and the first is the one that matters, because this key *is* the fabric.

`CertAuthority::intermediate` builds an ICAC's authority. §6.4.5.1 permits exactly one level —
"an Intermediate Certificate Authority whose ICA certificate is directly issued by such a Root
CA" — so an intermediate may issue NOCs and nothing else, and asking it for another ICAC is an
error rather than a longer chain.

## The commissioning flow

§5.5 lists seventeen steps for the initial phase and four for the setup phase. `Commissioner`
is that sequence as a state machine: it says what to send and takes what comes back, and the
caller keeps the sockets, the clock and the keys.

```rust,ignore
use matter_kit::commissioning::commissioner::{Commissioner, Plan, Stage, Step};

let mut commissioner = Commissioner::new(plan, challenge, attestation_nonce, csr_nonce);
loop {
    let step = match commissioner.stage() {
        Stage::AddTrustedRoot => commissioner.add_root(&ca, &keys)?,
        Stage::AddNoc => commissioner.add_noc(&ca, &keys, None)?,
        _ => commissioner.step()?,
    };
    match step {
        Step::Invoke { cluster, command, fields, .. } => {
            let response = send(cluster, command, fields).await?;
            commissioner.on_response(response.as_deref())?;
        }
        Step::Operational { node_id } => { /* network, discovery, CASE */ }
        Step::Done => break,
    }
}
```

The order is not a convenience. Every step depends on one before it, and several of the
dependencies are security properties rather than data flow:

- **The fail-safe is armed first** (§5.5 step 7), because everything after it is undone if the
  commissioner walks away. A device that took a NOC with no fail-safe armed would keep a fabric
  nobody finished joining.
- **Attestation comes before the CSR** (steps 10–11), because the CSR is signed by the *same*
  DAC key the attestation proved possession of. Asking for a CSR first would mean verifying a
  signature against a key nothing had vouched for.
- **The root goes in before the NOC**, and in the same fail-safe period (§11.18.6.8), or the
  device is asked to trust a chain whose anchor it does not have.

`Stage::Operational` is a deliberate pause. §5.5 steps 14–16 — the ACL, the Wi-Fi credentials,
the Thread dataset — are the caller's, because none of them is derivable: a commissioner that
guessed an SSID would be guessing about somebody's house.

### Attestation is reported, not enforced

§5.5 step 10 is explicit that failing §6.2.3 is not automatically fatal:

> the Commissioner MAY choose to either continue to the Commissioning, or terminate it,
> depending on implementation-dependent policies

and SHOULD warn the user. So `Commissioner` checks the signature and the nonce, and
`verify_attestation_against` checks the chain against a PAA *the commissioner* trusts — a device
supplying its own would be attesting to itself — and both report an `Attestation` rather than
ending the flow. The policy is the caller's, which is where the specification puts it.

A development device with an uncertified PAA is a case §5.5 explicitly wants commissionable,
with a warning.

## A development attestation chain

You cannot bring a device up without a DAC, and you cannot get a real one before certification.
`attestation::factory` builds the development counterpart:

```text
PAA  self-signed, CA, path length 1      "Matter Development PAA"
 └── PAI  CA, path length 0, Mvid        "Matter Development PAI, Mvid:FFF1"
      └── DAC  not a CA, Mvid + Mpid     "Matter Development DAC, Mvid:FFF1 Mpid:8000"
```

`0xFFF1`–`0xFFF4` are the vendor ids the CSA reserves for exactly this, and the builder refuses
anything else: a development chain claiming a real vendor's id is a forgery however
well-intentioned, and §6.2.2 gives a commissioner no way to tell the two apart except the id.

The VID and PID go in the Common Name, which is §6.2.2.2's *fallback* form — uppercase
hexadecimal, exactly four characters. §6.2.2.2's own example calls `Mvid:fff1` invalid, so a
factory that wrote lowercase would produce certificates its own verifier rejects.

## Watching what you commissioned

The client half of the interaction model is in `im::client`. Chunk reassembly was already there;
what a controller adds is the twin of a subscription.

```rust,ignore
use matter_kit::im::client::Subscription;
use matter_kit::im::encode_subscribe_request;

let request = encode_subscribe_request(&mut buf, paths, [], 5, 60, true, true)?;
// ...and when the SubscribeResponse comes back:
let mut held = Subscription::new(&response, now);
```

**The publisher chooses the interval.** §8.5.3.2 lets the server answer with a `MaxInterval` that
is not the ceiling that was asked for, so `Subscription` records what it was *told*. A subscriber
that assumed otherwise would declare a live subscription dead, tear it down and build another,
for ever — on a battery device, until the battery ran out.

**A keep-alive is proof of life.** §8.5.3: when nothing has changed by the maximum interval "the
publisher SHALL send an empty ReportData message", and its only job is to say the subscription is
still there. A subscriber that counted only *data* reports would tear down every subscription to
a device that simply is not changing, which is most devices, most of the time.

**And the deadline is not exact.** §8.5.4 says a subscriber "SHALL consider the subscription to
have expired" without saying when to start counting past the interval. Timing out at exactly
`MaxInterval` would tear down a working subscription on the first MRP retransmission, and over a
sleepy Thread network the first retransmission is not unusual.

## Fabric Synchronization and OTA

Two ecosystems, and a householder with a light in one that they want in the other. The usual
answer is to commission it twice. `clusters::commissioner_control` (§11.26) is the other answer:
the ecosystems arrange it between themselves, and the *roles reverse* — the server of the cluster
ends up as the commissioner and the client opens the window.

The flow is deliberately three steps with a pause:

> This is required to be a separate step in order to provide the server time for interacting with
> a user before informing the client that the CommissionNode operation may be successful.

So `RequestCommissioningApproval` always answers `SUCCESS` — it is a question — and the real
answer arrives later as a `CommissioningRequestResult` event. Both commands are CASE-only,
because the whole flow turns on matching a later `CommissionNode` to the *same node on the same
fabric*.

`clusters::ota_provider` (§11.20.6) hands out firmware. A `QueryImageResponse` carries a URI, not
bytes — the transfer itself is BDX, which arrives with M6 — and `DelayedActionTime` is the whole
flow-control mechanism: it is how a provider stops a hundred devices downloading, or rebooting,
at the same moment.

## Threads

The core is single-threaded by construction: one event loop, one `RefCell` per piece of state, no
atomics an MCU would have to pay for. A controller on a multi-threaded runtime is not, and the
`sync-mutex` feature is the seam — `sync::Shared<T>` is a `RefCell` without it and a
`std::sync::RwLock` with it. An `RwLock` rather than a `Mutex` so that both builds obey the same
rule: any number of shared borrows at once, or one exclusive borrow. Code that compiled under
one and deadlocked under the other would make the feature a behavioural change rather than a
threading one.

The rule that comes with it is not optional: **never hold a borrow across an `await`.** Take it,
use it, drop it before the next suspension point. A second *exclusive* borrow while one is live
panics at the mistake with a `RefCell` and deadlocks somewhere else with an `RwLock`, which is
why the device clusters keep their `RefCell`s — a device is single-threaded anyway, and the
single-threaded build is the one that finds the bug.
