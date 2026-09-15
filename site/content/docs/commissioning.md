+++
title = "Commissioning"
description = "From a printed passcode to a fabric member: PASE, device attestation, operational certificates, CASE, and the fail-safe that makes an interrupted attempt safe."
weight = 9
+++

Commissioning turns a factory-fresh device into a member of a fabric. Every step below is
implemented and exercised end to end against the specification's own published test vectors.

## PASE — the passcode never crosses the wire

The first thing any Matter device does is turn the eight-digit code on its label into an
encrypted session, using SPAKE2+ so that an attacker gets exactly one guess per exchange.

```rust,ignore
use matter_kit::crypto::Spake2pVerifierData;
use matter_kit::sc::{PaseResponder, PbkdfParameters, ResponderConfig};

// What a factory burns in. The device stores (w0, L) and *not* the passcode: reading its
// flash does not tell you what is printed on the label.
let parameters = PbkdfParameters::new(1_000, b"SPAKE2P Key Salt")?;
let verifier =
    Spake2pVerifierData::from_passcode(20_202_021, &parameters.salt, parameters.iterations)?;

let mut device = PaseResponder::new(
    ResponderConfig { verifier, parameters, session_params: None },
    SessionId(1),
);
```

Five messages later both ends hold `I2RKey`, `R2IKey` and an `AttestationChallenge`. The
implementation reproduces all four of the specification's published vectors byte for byte,
including the three with non-empty identities that Matter never uses but which exercise the
transcript's length prefixes.

## One guess per exchange is only half of it

SPAKE2+ gives an attacker exactly one passcode guess per handshake. What decides whether that
is enough is how many handshakes it is allowed, and Core §5.5 answers with three rules that
live outside the handshake — so `PaseResponder` does not enforce them, and
`commissioning::admission` does:

```rust
use matter_kit::commissioning::{Admit, PaseAdmission};
use matter_kit::platform::Instant;

let mut gate = PaseAdmission::new();
let now = Instant::ZERO;

// `commissionable` is the node's own answer to "am I in commissioning mode?" — a window is
// open, or there are no fabrics yet.
assert_eq!(gate.admit(true, now), Admit::Admitted);

// §5.5: "the Commissionee SHALL NOT accept any more requests for new PASE sessions" while
// one is in flight. Answer this one and the second commissioner replaces the first.
assert_eq!(gate.admit(true, now), Admit::Busy);
```

The rules, and what each is for:

| Rule | §5.5 | Without it |
|---|---|---|
| One handshake at a time | "SHALL NOT accept any more requests for new PASE sessions until …" | an attacker waits for the owner to start pairing, interrupts, and finishes the handshake in their place — no passcode guessing and no physical access |
| Sixty seconds to finish one | "SHALL expect a PASE session to be established within 60 seconds … SHALL terminate … using the INVALID_PARAMETER status code" | one unanswered request holds the channel, and the device never pairs again |
| Twenty failures ends commissioning mode | "the Commissionee SHALL exit Commissioning Mode after 20 failed attempts" | the passcode space is searched online, at whatever rate the network allows |

`admit` starts the sixty-second clock; `established`, `failed` and `closed` report what
happened, and `poll` is what the event loop calls to enforce the deadline. Time is a
parameter, so the sixty seconds is a unit test rather than a minute of waiting.

## Attestation — proving the device is genuine

The commissioner asks for three things and checks them against each other: a **Device
Attestation Certificate** chain rooted in a Product Attestation Authority, a **Certification
Declaration** signed by the Alliance, and a signature over a nonce plus the session's
attestation challenge.

Two properties are worth calling out:

- **The signature covers the attestation challenge**, which "SHALL NOT be included in any of
  the payloads conveyed". A signature made over it proves the signer is on *this* session,
  which is what stops a recorded attestation from being replayed.
- **"No product id" and "a malformed product id" must not be the same answer.** A
  Certification Declaration may legitimately omit the DAC-origin fields; it may not contain
  them in a form that does not parse. Collapsing the two accepts the second.

## Operational certificates

A Matter certificate is an X.509 certificate with everything Matter does not use taken out,
re-encoded in Matter TLV for the wire and in DER for the signature. Both forms are
implemented, and the specification's published RCAC, ICAC and NOC (§6.5.15) round-trip
through both.

The surprise: a Matter certificate's extensions are **not** in tag order and must not be
normalised into it. The encoding is what was signed; reordering it produces a certificate
that is byte-different from the one the CA issued, and the signature no longer verifies.

## The fail-safe

Everything from attestation onward runs inside a fail-safe — a timer the commissioner arms
and must keep re-arming. If it lapses, the device rolls back every credential, key and
network setting the attempt created.

Three rules that read like boilerplate and are not:

- **The cumulative timer is never extended.** Re-arming resets the expiry but not the total
  budget; otherwise an administrator can hold a device hostage forever by re-arming in a
  loop.
- **A lapsed context is reaped before the next is armed.** Expiring lazily means a re-arm
  inherits a half-commissioned state — a fabric that was added but never completed, adopted
  by whoever arms next.
- **The candidate operational key dies with the period.** §6.4.6.1: the key pair is "valid
  for the duration of the Fail-Safe Context currently in progress" and "SHALL only be
  committed to persistent storage upon successful execution of the next AddNOC".

## The credentials flow, end to end

```text
ArmFailSafe
  → CSRRequest                       device generates a key pair, signs a request
  → AddTrustedRootCertificate        the fabric's root
  → AddNOC                           the certificate issued over that request
  → (network configuration)
  → CASE                             a fresh session on the new credentials
  → CommissioningComplete
```

`CommissioningComplete` is CASE-only and fabric-matched: it is refused over the PASE session
that started the process, and refused from a fabric other than the one being commissioned.
Otherwise another node could complete a commissioning it did not perform.

## A second administrator

Once a device belongs to one fabric, a second ecosystem joins through the Administrator
Commissioning cluster: an existing administrator opens a temporary commissioning window with
a fresh verifier, and the new commissioner runs the whole flow again over it.

The window's own rules are exact — an armed fail-safe blocks opening one, `RevokeCommissioning`
acts even when no window is open, and only a *PASE-held* fail-safe is expired by a revoke.
Getting the last one wrong lets any administrator cancel another's commissioning.
