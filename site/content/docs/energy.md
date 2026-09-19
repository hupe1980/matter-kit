+++
title = "Energy"
description = "Device Energy Management, Energy EVSE, Water Heater Management and the measurement clusters — the ones an energy manager talks to."
weight = 6
+++

A car charger is the largest controllable load in most houses and almost the only one that does
not care *when* it runs, so long as it is full by morning. A hot water tank is a battery that
stores heat. A heat pump can modulate between a fifth and all of its rated power. The Matter
energy clusters exist so that something else — a tariff, a solar forecast, a grid signal — can
decide the hours in between.

Five clusters, and none of them is usable alone. §9.2.5 says so outright:

> This cluster does not report electrical power and electrical energy. Devices that use this
> cluster SHALL also support the Electrical Power Measurement and optionally support the
> Electrical Energy Measurement cluster to allow an energy management system to perform its
> role.

**Device Energy Management** negotiates, the **measurement** clusters answer "did it work?", and
the appliance cluster — **Energy EVSE**, **Water Heater Management** — does the thing.

## Seven features, seven negotiating positions

§9.2.4 splits flexibility into things an appliance may or may not physically be able to offer,
and the division is not arbitrary: "typically, appliances with a heating element cannot have
their power consumption adjusted and can only be paused or delayed". A washing machine offers
`STA` (delay the start) and `PAU` (pause mid-cycle). An inverter-driven heat pump offers `PA`
(run at this power). An EMS reads the feature map and knows which conversation it can have.

```rust,ignore
use matter_kit::clusters::device_energy_management::{DemHooks, DeviceEnergyManagement, feature};

let dem = DeviceEnergyManagement::new(&appliance, feature::POWER_ADJUSTMENT | feature::PAUSABLE);
```

Each command is gated on its feature twice over: the derived descriptor leaves it out of
`AcceptedCommandList`, and the handler refuses it. Those are two separate arguments a device can
get out of step, which is the only reason the second check earns its place.

## The user can always say no

`OptOutState` is the householder's veto, and it is not advisory. Every adjusting command carries
an `AdjustmentCauseEnum`, and one the opt-out forbids is `CONSTRAINT_ERROR` before anything else
is considered.

It is **per reason**, not a switch:

| `OptOutState` | local optimisation | grid optimisation |
|---|---|---|
| `NoOptOut` | permitted | permitted |
| `LocalOptOut` | refused | permitted |
| `GridOptOut` | permitted | refused |
| `OptOut` | refused | refused |

Someone who has opted out of grid optimisation may still want their own solar used, and a
cluster that collapsed the two would take that away.

## Overlapping adjustments do not each end

§9.2.9.1.4 explains itself:

> a battery inverter ESA may be sent a new request every 5 seconds to adjust its discharge power
> based on real-time meter readings. Each command may have a 60 second duration, but this command
> is superseded after 5 seconds by a new request.

So a replacement emits no `PowerAdjustEnd`, and no new `PowerAdjustStart` either — only the last
one to expire says anything. §7.14.2's event store is a fixed ring, and a cluster that reported
each of twelve adjustments a minute would push everything else out of it.

## Every enable has an end

The EVSE cluster is built around one idea: `ChargingEnabledUntil` is a *timestamp*, and "a value
in the past or 0x0 indicates that EVSE charging SHALL be disabled" (§9.3.8.4). So the ordinary
failure of a home energy manager — it crashes, the Wi-Fi drops — leaves the car charging until
the window it was given runs out, rather than for ever or not at all. The same section makes the
attribute persistent, "for example a temporary power failure should not stop the vehicle from
being charged".

Charging and discharging are **two axes**, not three states. Enabling charging from `Disabled`
gives `ChargingEnabled`; enabling it while discharging gives `Enabled`; each window expiring
drops back to whatever the other still allows. A device that treated `SupplyState` as a single
mode would turn vehicle-to-home off every time a charge window ended.

```rust,ignore
use matter_kit::clusters::energy_evse::{EnergyEvse, EvseHooks};

// `T` is how many charging targets one day may hold.
let evse: EnergyEvse<'_, WallBox, 10> = EnergyEvse::new(&wall_box, feature::CHARGING_PREFERENCES);
evse.start(stored_charging_until, stored_discharging_until);
```

Those timestamps are `epoch-s`, in UTC, and a monotonic clock cannot compare them. `EvseHooks::utc`
is where they come from; an EVSE whose clock has never been set reports `None` and then never
expires a window on its own. Guessing would either cut a charge short or run one past the hour
the user was quoted.

Every EVSE command is `OT` — Operate *and Timed*. §8.7.4's Timed transaction is what stops an
`EnableCharging` meant for two in the morning arriving at six in the evening.

## One Mode Base, ten clusters

Ten clusters in the 1.6 library are "derived from the Mode Base cluster and define additional
mode tags and namespaced enumerated values" — Energy EVSE Mode, Water Heater Mode, Dishwasher
Mode, Laundry Washer Mode and six more. They differ in their id, their PICS code and their tags,
and in nothing else. So there is one implementation, and the cluster id is a const parameter:

```rust,ignore
use matter_kit::clusters::generated::energy_evse_mode;
use matter_kit::clusters::mode::Mode;

let mode = Mode::<_, { energy_evse_mode::ID }>::new(
    &energy_evse_mode::CLUSTER, &appliance, SUPPORTED_MODES, 0,
)?;
```

A const parameter rather than a field, because `Cluster::ID` is an associated constant and that
is what lets a tuple dispatch. One implementation therefore produces ten distinct *types* —
which is exactly right for an endpoint that has two mode clusters.

`Mode::new` enforces §1.10.6.1 at construction: at least two modes, every `Mode` unique, every
`Label` unique, and every *set* of mode tags distinct from the others. A device that shipped two
modes a controller could not tell apart would leave a user picking between identical entries in
a list, with no way to know why.

`ChangeToMode` answers inside its response, not with an interaction-layer status: §1.10.7.1.1
wants a `StatusText` a person can read, and that is what tells them why the dishwasher would not
switch to Heavy.

## Null is the honest reading

Every measured value in the two measurement clusters is nullable, and the specification means
it. A meter that has not taken a reading, or whose sensor has failed, reports null — not zero.
Zero is a measurement; it says the appliance is drawing nothing. An energy manager that could
not tell the two apart would balance a house against a number nobody measured.

`Accuracy` is mandatory and it is not decoration. A current-transformer clamp is worth ±2% above
a couple of amps and nearly nothing below; an EMS that treated a 15 W reading from one as exact
would chase noise all evening.

And **Power Topology** says what the meter is measuring at all — the whole node, an endpoint and
its children, or a named set. A measurement without a scope is a number with no meaning: 400 W
could be the house, one socket, or a circuit.

## What a whole EVSE looks like

```text
endpoint 0   Root Node
endpoint 1   Energy EVSE          Device Energy Management, Energy EVSE, Energy EVSE Mode
endpoint 2   Electrical Sensor    Power Topology, Electrical Power/Energy Measurement
```

Two endpoints, serving different clusters, which is what
[routing by endpoint](@/docs/clusters.md#more-than-one-endpoint) is for.
`tests/energy.rs` builds exactly that node and checks both endpoints against the Device Library
before it asserts anything else.
