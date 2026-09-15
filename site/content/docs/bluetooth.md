+++
title = "Bluetooth"
description = "Commissioning over BLE: the advertisement a commissioner scans for, and BTP — the segmentation and flow control that fit a 1280-octet Matter message through a 20-octet GATT pipe."
weight = 11
+++

A device that has never been on a network cannot be found on one. BLE is how Matter solves
that: the device advertises, a commissioner connects, and PASE runs over the connection until
the device has credentials and an operational network to join.

Two pieces make it work, and `matter_kit::transport` is both of them. [`ble`] is the surface
against the radio — the GATT service, and the advertisement a commissioner scans for. [`btp`]
is the protocol that carries Matter messages across it.

[`ble`]: https://docs.rs/matter-kit/latest/matter_kit/transport/ble/
[`btp`]: https://docs.rs/matter-kit/latest/matter_kit/transport/btp/

## The advertisement carries everything

§5.4.2.5.6 explains why there is no scan response:

> In order to reduce 2.4 GHz spectrum congestion due to active BLE scanning, and to extend
> battery life in battery-powered devices, all critical data used for device discovery is
> contained in the Advertising Data rather than the Scan Response Data.

So a commissioner scanning passively already has what it needs — the 12-bit discriminator it
matches against the QR code — and never transmits at all.

```rust,ignore
// The device advertises what its own label says.
let advert = Advertisement::for_onboarding(&payload);
let n = advert.encode(&mut air)?;

// A commissioner finds the Matter service data wherever it sits in the payload.
if let Ok(Advertisement::Commissionable { discriminator, .. }) = Advertisement::decode(&seen) {
    // ...and matches it against the discriminator from the QR code.
}
```

Deriving the advertisement from the onboarding payload is not a convenience. If the two
disagree on the discriminator the device is simply never found, and the failure looks like a
radio problem rather than a wrong number.

A device may drop its vendor and product from the advertisement for privacy. Both go or
neither does: "A device SHALL NOT set the VID to 0 when providing a non-zero PID", and
`encode` refuses it.

## The pipe is twenty octets wide

A GATT PDU carries `ATT_MTU - 3` octets. On the minimum MTU that is **20**, and a Matter
message may be 1280. BTP (§4.19) is what bridges the gap: it cuts a message into segments,
numbers them, and reassembles them on the far side.

```rust,ignore
let agreed = negotiate(&request, own_att_mtu, own_window)?;
let mut session = Session::<1280>::new(Role::Server, &agreed, now);

session.send(&matter_message)?;
while let Some(n) = session.poll_send(now, &mut gatt)? {
    // ...write it to C1, or indicate it on C2.
}
```

Like everything else here it is sans-I/O: bytes and a clock reading in, bytes and deadlines
out. Which BLE stack drives the radio is the platform's business, because that is where every
platform differs.

## The receive window is not an optimisation

This is the part of BTP that is easiest to implement almost-correctly. §4.19.4.7 gives the
reason it exists, and it is physical:

> In the case of some dual-chip architectures, writes and indications are received and
> confirmed by the BLE chip with no input from the host processor. When the BLE chip sends the
> result of a received GATT PDU to the host processor, that payload and the corresponding BTP
> packet will be permanently lost if the host does not have enough space to receive it.

The window is how a peer says "I can hold this many more before something is dropped on the
floor". Exceeding it loses data with no error raised anywhere. Three rules keep it from
deadlocking instead, and each is easy to leave out:

- **The last slot is reserved.** A peer must not send when the remote window has one slot left
  and it owes no acknowledgement. Otherwise both windows fill and neither side can send the
  acknowledgement that would reopen them.
- **The two ends start differently.** A server's handshake response "bears an implied sequence
  number of zero because it occupies a slot in the client's receive window", so a server
  starts its counter at `max - 1` and its first data packet at sequence 1, while a client
  starts at `max` and sequence 0. Starting both the same desynchronises the session on its
  very first packet.
- **A nearly-full window speaks up early.** A peer whose own window is down to two free slots
  sends its pending acknowledgement immediately rather than waiting for the timer — otherwise
  the session stalls for the length of that timer every time the window fills.

## Acknowledgements are not free

> In contrast to TCP, BTP acks are not "free." A stand-alone ack — that is, a BTP packet that
> contains a packet receipt acknowledgement value but no buffer segment payload — consumes a
> slot in a remote peer's window just like any other packet.

So an acknowledgement rides on the next outgoing segment whenever there is one. The
send-acknowledgement timer is what forces it out when there is not, and the
acknowledgement-received timer is what notices when one never comes back. Because an idle
session still exchanges acknowledgements, that second timer doubles as BTP's keep-alive: a
remote stack that crashes simply stops answering, and the session closes.

## A closed session stays closed

A sequence number that does not increment by one, an acknowledgement for a packet never sent,
a reassembly that does not match its declared length, an Ending segment with no Beginning:
§4.19.4.5 and §4.19.4.6 close the session for each of these. BTP has no way to resynchronise,
so a session that carried on would splice two messages into one.

`Session` latches that. Once it has closed, every call reports the same reason —
`is_closed()` and `close_reason()` say so — because a caller that misses the first error must
not be handed a working session back.

## MRP does not run on top of it

Matter has its own reliability protocol, and over BLE it stays out of the way. §4.12.4:

> Reliable messages sent over TCP, PAFTP, or BTP SHALL utilize the underlying reliability
> mechanisms of those transports and SHOULD NOT set the R Flag.

Two mechanisms guaranteeing the same delivery is not twice as safe: MRP would retransmit a
message BTP has already delivered, and BTP would faithfully carry the duplicate. `Messaging`
enforces it from the transport rather than trusting each caller to remember — an exchange
opened with `open_to(.., Peer::Ble(handle), ..)` never sets the flag, and arms no timer.

## What is here and what is yours

The protocol is here: frames, the handshake, segmentation and reassembly, sequence numbers,
the window, the timers, and the advertisement. `tests/commission_over_btp.rs` runs a
commissioner and a device through the whole of it — advertisement, handshake, and all five
PASE messages segmented across the connection — at both ends of the MTU range.

The radio is yours. The GATT server, the two characteristics, the subscription, and the
advertising interval are where `nrf-softdevice`, `esp32-nimble`, BlueZ and CoreBluetooth all
differ, and a trait covering them would fit none of them well. [`ble`] gives you the UUIDs
and payload formats those stacks need; what drives them is platform code.
