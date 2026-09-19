+++
title = "Clusters and conformance"
description = "The Matter cluster library, generated from the CSA data model — and the conformance engine that decides which of a cluster's elements a device may serve."
weight = 5
+++

A Matter cluster is not a list of attributes. It is a list of attributes *each of which may or
may not exist*, decided by the feature map the device claims. On/Off's `StartUpOnOff` is
mandatory with the Lighting feature and **forbidden** without it. Its `On` command is mandatory
unless `OffOnly` is set. Level Control's `CurrentFrequency` is mandatory with `FQ` and
disallowed without.

There are several thousand rules like that in the 1.6 library, and transcribing them by hand is
months of work with a silent drift risk. A device whose descriptors disagree with them looks
fine, passes its own tests, and fails certification for a reason nothing in its own suite could
have found.

So they are generated.

## Where they come from

`cargo xtask` reads the CSA's machine-readable data model — the same XML the Test Harness itself
reads — and writes `matter_kit::clusters::generated`: 135 clusters and 91 device types, with
every element's access, qualities and conformance.

```rust,ignore
use matter_kit::clusters::generated::on_off;

assert_eq!(on_off::ID, 0x0006);
assert_eq!(on_off::REVISION, 6);
assert_eq!(on_off::feature::LIGHTING, 1 << 0);

// The enumerations are Rust enums, and a reserved wire value is `None` rather than a guess.
assert_eq!(on_off::StartUpOnOffEnum::from_value(2), Some(on_off::StartUpOnOffEnum::Toggle));
assert_eq!(on_off::StartUpOnOffEnum::from_value(9), None);
```

The XML is not in the repository — it carries the CSA's own copyright notice and is not
redistributable — but the generated Rust is, so a build needs no download and docs.rs shows
real types. A CI job regenerates and fails on any difference, which is what stops the library
drifting from the specification it claims to be.

## Conformance is a statement about existence

`[LT]` does not mean "optional, and by the way there is a feature". It means the element may
exist *only when* Lighting does. That distinction is the whole engine:

```rust,ignore
use matter_kit::clusters::generated;

let on_off = generated::find(0x0006).unwrap();
let mut defects = Vec::new();
on_off.validate(&my_descriptor, |defect| defects.push(defect));
```

Five kinds of mistake come out, and the first two are the ones a device makes by accident:

- a **mandatory element missing** — the feature map claims Lighting and the descriptor has no
  `StartUpOnOff`;
- a **disallowed element present** — `StartUpOnOff` served without Lighting, which a
  commissioner reads as a device that does not know what it is;
- a feature bit the revision does not define;
- a `ClusterRevision` that is not the specification's, which is the single most commonly stale
  number in any implementation;
- a response command in the *accepted* list, which advertises that a client may invoke the
  server's own reply.

An element whose rule the XML could not express is skipped in both directions. The
specification's own words decide it, and a validator that guessed would be the confident-wrong
kind nobody trusts.

## Let the specification write the descriptor

The engine also runs the other way. Give it a feature map and say which *optional* elements
your product implements — optionality is a decision the product makes, not one conformance can
derive — and it produces the descriptor:

```rust,ignore
use matter_kit::clusters::generated::on_off;
use matter_kit::dm::spec::{Conforming, Optional};

// A plain relay: one attribute, three commands.
let plain = Conforming::<8, 8, 4, 4>::new(&on_off::CLUSTER, 0, &Optional::NONE)?;
assert_eq!(plain.descriptor().attributes.len(), 1);

// A light: `StartUpOnOff` and its three companions appear, and so do three more commands,
// without a line of it being written down anywhere.
let lighting =
    Conforming::<8, 8, 4, 4>::new(&on_off::CLUSTER, on_off::feature::LIGHTING, &Optional::NONE)?;
assert_eq!(lighting.descriptor().attributes.len(), 5);
```

A descriptor built this way *cannot* advertise an attribute its features forbid. That is not a
theoretical benefit: the validator found exactly that bug twice in this crate's own
hand-written clusters, in code that had passed every test written for it.

## Device types are a claim

An endpoint advertises its device types in the Descriptor cluster, and a commissioner reading
"On/Off Light" expects Identify, Groups, On/Off and Scenes Management to be there. A device
that advertises the type without furnishing it appears in an app and then does not work — a
worse failure than not appearing at all.

```rust,ignore
use matter_kit::clusters::{generated, validate_endpoint};

let light = generated::device_types::ON_OFF_LIGHT;
validate_endpoint(&endpoint, &light, |defect| eprintln!("{defect:?}"));
```

It checks more than the cluster list, because a cluster list cannot say any of the three things
that actually distinguish one device type from another:

- **Features.** An On/Off Light does not merely require On/Off, it requires On/Off **with
  Lighting** — a light without the feature has no `StartUpOnOff`, so it comes back on in
  whatever state it was in, which is the behaviour the device type exists to rule out.
- **Individual elements.** A device type may tighten its clusters' own conformance. §1.2.6
  calls Identify's `TriggerEffect` optional; §4.1's On/Off Light makes it mandatory, and so is
  Scenes Management's `CopyScene`. A check that compared cluster ids alone would pass an
  endpoint whose app screen has a dead button.
- **Direction.** A device type's *client* entries name what the endpoint binds to rather than
  what it serves. An On/Off Light Switch is not asked to implement an On/Off server — but it
  *is* asked to declare an On/Off client, in the endpoint's `ClientList`, because consuming
  On/Off is the only thing that tells a switch apart from the light it controls.

```rust,ignore
// A switch serves Identify and binds to On/Off. Both halves are part of the claim.
let endpoint = Endpoint::new(1, &switch_clusters).with_clients(&[0x0003, 0x0006]);
```

This belongs in your tests rather than your start-up path. Each cluster's tables are `const`
data, so the linker drops every one your device does not name — but resolving a feature code
reaches `generated::find`, which names all of them, and a device that serves three clusters
would then carry the whole library.

## Behaviour still has to be written

The tables say what a cluster *is*. A few clusters also define what one *does*, and those are
written by hand over the generated types — On/Off is the first:

```rust,ignore
use matter_kit::clusters::on_off::{OnOff, OnOffHooks};

struct Lamp;
impl OnOffHooks for Lamp {
    fn set(&self, on: bool) { /* drive the pin */ }
}

let cluster = OnOff::new(&lamp, on_off::feature::LIGHTING, None);
```

That is all a light implements. §1.5.7's state machine — `OnWithTimedOff`'s two counters, the
global scene, the startup behaviour — belongs to the cluster, and the guard at the centre of it
exists for a situation the specification describes in plain words:

> when leaving a room, the lights are turned off but an occupancy sensor detects the leaving
> person and attempts to turn the lights back on

A device that reimplemented any of that would be reimplementing the part certification tests.

## Numbers this stack does not own

The three network diagnostics clusters — Ethernet (§11.16), Wi-Fi (§11.15) and Thread (§11.14) —
report counters, signal strengths and neighbour tables that belong to an interface `matter-kit`
has no access to. So each is a **driver trait** you implement, with a default for every method,
and none of them needs a radio to compile or to test.

```rust,ignore
use matter_kit::clusters::wi_fi_network_diagnostics::{
    SecurityTypeEnum, WiFiDriver, WiFiNetworkDiagnostics, feature,
};

struct Radio;
impl WiFiDriver for Radio {
    fn bssid(&self) -> Option<[u8; 6]> { Some(self.ap_mac()) }
    fn security_type(&self) -> Option<SecurityTypeEnum> { Some(SecurityTypeEnum::WPA3) }
    fn rssi(&self) -> Option<i8> { Some(self.signal_dbm()) }
    fn beacon_rx_count(&self) -> Option<u32> { Some(self.beacons()) }
    fn reset_counts(&self) { self.zero_counters(); }
}

// `PKTCNT`, because this driver counts beacons. Claiming a feature is a promise.
let cluster = WiFiNetworkDiagnostics::<_, 4>::new(&radio, feature::PACKET_COUNTS);
```

**The return type tells you how many answers the specification allows**, and that differs between
the three:

- `Option<T>` — the attribute is mandatory and nullable, so there are two answers: a value, or
  `null`, meaning the interface is not currently configured or operational. Almost everything on
  Wi-Fi and Thread is this. You cannot say "my device does not report `RSSI`", because a Wi-Fi
  device does.
- `Reading<T>` — the attribute is optional *and* nullable, so there is a third answer:
  `Reading::Unsupported`, which also keeps the attribute out of `AttributeList`. Ethernet's
  `PHYRate`, `FullDuplex` and `CarrierDetect` are this; on Wi-Fi only `CurrentMaxRate` is.
- A slice — the attribute is a mandatory list, and empty is a perfectly good answer. Thread's
  `NeighborTable`, `RouteTable` and `ActiveNetworkFaultsList`.

Get that wrong and an attribute is either answered but not advertised — a number no client can
find — or advertised but not answered, which is a read that fails.

**Claiming a feature is a promise you can count.** A device that advertises `ERRCNT` and reports
zero collisions forever tells a support engineer the link is clean. So an unclaimed counter is
refused rather than answered as zero, and it stays out of `AttributeList`.

Thread's thirty-four `MACCNT` counters and eight `MLECNT` counters arrive as two structs,
`MacCounters` and `MleCounters`, because that is how a Thread stack hands them over. Every field
is `Option`: a counter is optional *within* its feature, so one you leave `None` belongs out of
the optional set the descriptor is built from too.

**Events are the driver's to notice.** Wi-Fi's `Disconnection`, `AssociationFailure` and
`ConnectionStatus`, and Thread's `ConnectionStatus` and `NetworkFaultChange`, are recorded on the
cluster and drained by the device into its own event store:

```rust,ignore
for event in wifi.take_events() {
    let mut payload = [0u8; 64];
    let mut w = TlvWriter::new_in(&mut payload, ContainerKind::Structure);
    event.encode(&mut w, Tag::Context(7))?;
    events.record(&NewEvent {
        endpoint: 0,
        cluster: wi_fi_network_diagnostics::ID,
        event: event.id(),
        priority: event.priority(),
        timestamp: Timestamp::System(now.as_millis()),
        fabric_index: None,
        data: w.finish()?,
    })?;
    subscriptions.note_event(0, wi_fi_network_diagnostics::ID, event.id());
}
```

The queue is bounded and drops its oldest rather than refusing, so a radio that flaps cannot make
the cluster fail.

One last difference, which looks like a mistake until you check it: `ResetCounts` is conditional
on `PKTCNT | ERRCNT` on Ethernet and on `ERRCNT` alone on Wi-Fi and Thread. A Wi-Fi device that
counts packets and no errors genuinely has no `ResetCounts`.

## More than one endpoint

A tuple of clusters dispatches on the cluster id, which is all a single-endpoint device needs.
The moment a node has two endpoints the id stops being an address: every endpoint has its own
Descriptor (§9.5), and a two-gang switch has On/Off twice. `At` supplies the missing half and
`Endpoints` routes on it — endpoint first, cluster second, the order a concrete path names them
in.

```rust,ignore
use matter_kit::clusters::{At, Endpoints};

let handler = Endpoints((
    At::new(0, (Descriptor::new(node, 0).with_parts(&[1]), &commissioning, /* ... */)),
    At::new(1, (Descriptor::new(node, 1), &identify, &groups, &lamp, &scenes)),
));
```

A path naming an endpoint no member holds is `UNSUPPORTED_ENDPOINT` rather than another
endpoint's data.

## The clusters a light owes a commissioner

Four clusters make an endpoint an On/Off Light, and three of them are about being *found* and
*grouped* rather than about light:

- **Identify** (§1.2) is one countdown. `IdentifyTime` seconds, decremented once a second, and a
  hook called on the transition — not on every tick, because §1.2.5.1 asks for a half-second
  blink and a device that re-armed each second would blink in lockstep with the clock instead.
  It catches up on elapsed time rather than counting calls, so a device that polls late stops
  identifying when it said it would.
- **Groups** (§1.3) is what makes "turn off the kitchen" one message rather than six. The table
  is scoped twice over: per endpoint, because a two-gang switch's gangs are in different rooms,
  and per fabric, because a device that let one ecosystem see another's groups would hand
  whoever commissioned it second a map of the house.
- **Scenes Management** (§1.4) stores a set of attribute values per group and recalls them.

```rust,ignore
use matter_kit::clusters::groups::Groups;
use matter_kit::clusters::identify::{Identify, IdentifyTypeEnum};
use matter_kit::clusters::scenes::{SceneTable, Scenes};

// The Scene Table is a value of its own, because two clusters hold it: §1.3.7.4 makes
// `RemoveGroup` remove that group's scenes — a rule about the Scene Table, written in the
// Groups chapter. Building it first is what lets both borrow it without a cycle.
let scene_table = SceneTable::<16, 128, 5>::new(true);
let identify = Identify::new(&lamp, IdentifyTypeEnum::LightOutput);
let groups = Groups::with(4, true, &identify, &scene_table);
let scenes = Scenes::new(&scene_table, &groups, &lamp, true);
```

Three rules in that trio are the ones a device gets wrong in ways nobody notices until two
ecosystems share the house:

**A groupcast gets no answer.** Every command in both clusters says "SHALL NOT generate a ...
Response command" when the request arrived as a groupcast. The work still happens; the response
does not, because one multicast reaching twenty lights would otherwise draw twenty unicast
replies at the same instant, on a network chosen for low power rather than burst capacity.

**No fabric may take more than half the Scene Table.** §1.4.6 spells out the arithmetic, and
without it whoever commissions first fills the table and the second ecosystem cannot store a
single scene.

**Removing a group removes its scenes.** §1.3.7.4 and §1.3.7.5, written in the Groups chapter
about the Scenes cluster's data — which is exactly why an implementation skips it, and then
accumulates scenes addressed to groups it has left: storage nobody can reach and nobody can
reclaim.

What the Scenes cluster does *not* know is which attributes carry §7.13's Scenes quality or
what setting one means. That belongs to the clusters that own them, behind a `SceneHooks` pair:
`capture` writes the endpoint's current state, `apply` puts it back. The cluster stores bytes
and hands them back in the order they arrived.

## Two commands that look identical

Level Control (§1.6) has `MoveToLevel` and `MoveToLevelWithOnOff`, which take the same fields
and do nearly the same thing. §1.6.4.1.2 says what separates them:

> The first set is used to maintain independence between the CurrentLevel and OnOff attributes
> ... As examples, this represents the behavior of a volume control with a separate mute
> button, or a 'turn to set level and press to turn on/off' light dimmer. The second set is
> used to link the CurrentLevel and OnOff attributes.

Two products, and a device that implemented one set and aliased the other would be one of them
pretending to be the other.

The rule that follows from it is §1.6.6.9's gate: a `MoveToLevel`, `Move`, `Step` or `Stop` —
the ones *without* On/Off — does nothing at all when the On/Off cluster on the same endpoint
says the device is off, unless `ExecuteIfOff` is set. That is what stops a dimmer winding a
switched-off lamp up to full, so that turning it on later blinds somebody.

And the bit is not read from the attribute directly. Every affected command carries
`OptionsMask` and `OptionsOverride`, and the value in force is the attribute with the masked
bits replaced — so a client can say "this once", in both directions, without writing an
attribute the specification calls "meant to be changed only during commissioning".

```rust,ignore
use matter_kit::clusters::level_control::{LevelControl, LevelControlHooks};

// Coupled to the On/Off cluster on the same endpoint, so the 'with On/Off' commands work.
let dimmer = LevelControl::with_on_off(&lamp, &on_off_cluster, feature::LIGHTING | feature::ON_OFF);
dimmer.start(previous_level);
```

With it, `Dimmable Light` (§4.2) is expressible — and that device type is where the
element-level checks earn their keep: it demands `MinLevel` and `MaxLevel`, which Level Control
itself calls optional, because a controller that cannot read the range has no idea what "50"
means on a particular lamp.

Level Control is not the last cluster with behaviour — see [Energy](@/docs/energy.md) for the
five that let a tariff, a solar forecast or a grid signal decide when a car charges.

## A bridge

A bridge is one Matter node presenting devices it does not contain — a Zigbee gateway, a
Z-Wave hub, a cloud integration. Core §9.12 gives it a shape:

```text
endpoint 0   Root Node        the node itself
endpoint 1   Aggregator       PartsList = [2, 3]
endpoint 2     Bridged Node + On/Off Light      a Zigbee bulb
endpoint 3     Bridged Node + On/Off Light      a Z-Wave switch
```

Two device types on one endpoint is the normal case here, and they answer different questions:
**Bridged Node** says what the endpoint is attached to, **On/Off Light** says what it does.

`PartsList` is not decoration. §9.13: "This cluster SHALL NOT be used on an endpoint that is
not in the Descriptor cluster PartsList of an endpoint with an Aggregator device type" — the
tree is the rule.

### Say only what you know

Bridged Device Basic Information is Basic Information with the *node's* facts taken out.
§9.13.5 marks `DataModelRevision`, `Location`, `CapabilityMinima` and three more **disallowed**,
because those describe the Matter node doing the bridging, not the bulb behind it. Almost
everything that remains is optional, and the specification is unusually explicit about why:

> For such cases where the information for a particular attribute is not available, the Bridge
> SHOULD NOT include the attribute in the cluster for this Bridged Device.

So an attribute the bridge cannot fill is left out of `AttributeList` rather than sent as an
empty string — a client can then tell "the bridge does not know the vendor" from "the vendor is
called nothing". `BridgedDevice`'s fields are `Option`, and `optional_for` turns what the bridge
actually knows into the optional set the descriptor is derived from, so the two cannot drift.

### Losing a device

A `no_std` node's endpoint set is fixed at build time, and §9.13.5.2 is the reason that is the
right shape rather than a limitation. When a bridged device stops answering the endpoint does
**not** disappear: `Reachable` goes false and `ReachableChanged` is emitted once — on the
change, not on every poll, because the event store is a fixed ring and a chatty record pushes
out everything else in it. A controller that had a binding or a scene pointing at that endpoint
still has one. An endpoint that vanished and came back renumbered would break every one.

`examples/bridge` is the whole assembly, and it checks its own claims: every endpoint is run
through `validate_endpoint` before it prints anything.

`examples/light` is the whole assembly: two endpoints, a root endpoint carrying the eleven
clusters a commissioned node owes — Descriptor, Binding, Access Control, Basic Information,
General Commissioning, General Diagnostics, Administrator Commissioning, Operational Credentials,
Group Key Management and both Label clusters — and an endpoint 1 that claims `On/Off Light` and
furnishes it. `tests/device_types.rs` runs `validate_endpoint`
over the very descriptors the example builds, so the claim cannot outlive the furnishing.

**Access Control keeps the audit trail, and a device has to let it.** §9.10.9.1 asks for an
`AccessControlEntryChanged` for every entry added, changed or removed, carrying the entry's new
value and naming who did it — the node id over CASE, the passcode id over PASE. Three things
about that are easy to get wrong and invisible afterwards:

- The entry `AddNOC` creates is an ACL change like any other, and it is the entry every other one
  on that fabric is granted by. Added straight to the list rather than through the cluster, it
  appears in no audit trail at all: the record begins by omitting the grant everything else
  derives from.
- A whole-list write is compared **position by position**. A list attribute's entry is its index,
  so replacing `[admin]` with `[admin, operator]` changes one and adds one. Reporting it as a
  removal and two additions tells a controller it has lost an entry it still has.
- The cluster records what happened; the *device* turns each record into an event and tells the
  subscription table about it. A device that does the first and not the second answers every read
  correctly and leaves a subscriber that asked to be told waiting out its maximum interval.
