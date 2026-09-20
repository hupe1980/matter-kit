+++
title = "The data model"
description = "How matter-kit serves Reads, Writes, Invokes and Subscriptions: wildcard expansion, the two-stage access check, events, the Timed transaction window, chunking in both directions, and atomic writes."
weight = 4
+++

A node's shape is `const` data and a `Server` walks it. What makes the walk interesting is
not the traversal — it is what a client is *told* when something is refused.

## A concrete path and a wildcard are answered differently

Specification §8.4.3.2 handles failure in two ways depending on how the path was written:

> b. Else if the path is a concrete path … an `AttributeStatusIB` **SHALL be generated** with
>    the `UNSUPPORTED_ENDPOINT` Status Code.
>
> c. Else perform Request Path Expansion … the path **SHALL be discarded**.

A client that asked for one attribute is told why it cannot have it. A client that asked for
everything simply does not see it. Reporting statuses for wildcard expansions would work
perfectly well and would let a subject with no privilege over a cluster learn the cluster is
there by counting the refusals.

A concrete path is also access-checked **twice**, and the first check comes *before* the
existence checks — so an unprivileged subject gets `UNSUPPORTED_ACCESS` rather than
`UNSUPPORTED_CLUSTER`, and cannot map a node it has no rights over.

Both properties are tested by breaking them: the suite has cases that fail if the order is
swapped or the discard becomes a status.

## Writes and invokes mirror reads, with three differences

A write additionally checks the `T` (Timed) quality, the accessing fabric and the client's
cached `DataVersion`. An invoke checks Timed, the fabric, and whether the transport can
carry a Large Message — §7.7.5's `L` quality "SHALL require TCP", and no privilege
substitutes for a transport.

Three places where a symmetric implementation would be wrong:

- **A write reports success explicitly.** §8.7.3.3 generates a `SUCCESS` status for every
  path written, where a read reports success by returning data.
- **An invoke's first access check is at Operate, not View.** There is no such thing as a
  read-only command: View is enough to look at a node and never enough to make it do
  something.
- **The fabric check applies to a concrete write and not to an expanded one.** §8.7.3.2
  discards a fabric-scoped concrete path with no accessing fabric; the expansion branch has
  no such rule, because §8.7.3.3 instead processes the path as a fabric-filtered list.
  Implementing the symmetric version silently drops writes a conforming client expects to
  land.

A response command's path is **rebuilt**, not echoed: the response keeps the request's
endpoint and cluster and takes the *response* command's id, so a server that echoed the
request path would send something a client cannot match to the command it defines.

And a write's access decision is taken **once per path per action**, not once per
`AttributeDataIB`. §10.6.4.3.1's way of replacing a list is a series of blocks that all name the
same attribute — the first clearing it, the rest appending — and on the `ACL` attribute the
first one removes the administrator entry the writer is administering with. Re-checking on each
block answers `UNSUPPORTED_ACCESS` to every append after the clear and leaves the node with no
administrator at all. Carrying the decision cannot widen anybody's access: it reuses a grant
checked against the list as it stood when the action began, and a *refusal* is never carried.

## Global attributes are synthesised

The five global attributes of §7.13 — `ClusterRevision`, `FeatureMap`, `AttributeList`,
`AcceptedCommandList`, `GeneratedCommandList` — are derived from the cluster's descriptor
rather than implemented by each cluster. `AttributeList` is a list *of* the descriptor's
contents, and a hand-maintained copy is one that drifts from what the cluster actually
serves.

## Subscriptions

A subscription is a standing read, and the only interaction where the publisher decides when
to speak. Two intervals pull in opposite directions:

- `MinIntervalFloor` — the subscriber's protection against a flapping sensor.
- `MaxIntervalCeiling` — the subscriber's liveness check.

The negotiated maximum has a bound that is easy to read backwards. §8.5.3.2:

> `MinIntervalFloor` ≤ `MaxInterval` ≤ `MAX(SUBSCRIPTION_MAX_INTERVAL_PUBLISHER_LIMIT,
> MaxIntervalCeiling)`

The upper bound is the **larger** of the publisher's own limit and what the subscriber
asked for, so a publisher may legally stay silent longer than the subscriber's ceiling.
That is what an intermittently connected device needs — its limit is "the Idle Mode Duration
or 60 minutes, whichever is greater". Every instinct says a negotiated value should be
bounded below both parties' requests. Here it is not.

Subscribed paths stay **wildcards**. Expanding them at subscribe time would be cheaper per
report and would mean a subscription to "every attribute of cluster 6" never notices an
endpoint added later.

### Every fabric is promised three

§2.11.2.2 words the limit as a guarantee, not a cap:

> A publisher SHALL ensure that every fabric the node is commissioned into can support at least
> three Subscribe Interactions to the publisher.

A single global limit cannot keep that promise, and the way it breaks is quiet: the first
ecosystem to connect fills the table, and the second is told the device is out of resources — by
a device that, from its own point of view, is working perfectly. It is the same multi-admin
isolation failure the ACL's per-fabric quota exists to prevent, so it is solved the same way: a
fixed share each, refused even when the table has room.

```rust,ignore
// Refused because *this fabric* is at its share, not because the node is full.
Err(SubscribeError::FabricQuota) => { /* RESOURCE_EXHAUSTED on the wire */ }
Err(SubscribeError::Full)        => { /* also RESOURCE_EXHAUSTED — but a different fix */ }
```

Both answer `RESOURCE_EXHAUSTED`, because there is no status code for "not yours". They are
separate variants so that an integrator reading a log can tell "the table wants to be longer"
from "this administrator is using more than its share" — and only the first is a number to
change.

The share itself is `Config::SUBSCRIPTIONS_PER_FABRIC`, and the table is asserted at compile time
to hold `FABRICS` × that many. A node cannot advertise a guarantee it has no room for, which is
what `SubscriptionsPerFabric` in `CapabilityMinima` would otherwise be.

A subscription with **no accessing fabric** — over PASE — is the one case the specification
leaves open: permitted "subject to available resources", a `MAY`. It gets only what is not
promised to a fabric, because a `MAY` must never spend a `SHALL`.

## Events

An event has no attribute to live in; it exists only as something that happened. The store
is one ring buffer **per priority** — Critical, Info, Debug — each sized independently,
because §7.14.2 makes priority a retention *guarantee* rather than a scheduling hint. A
single shared ring cannot honour that under any eviction policy: evict by age and a Debug
flood walks out the Critical record in milliseconds.

Within a ring the newest record overwrites the oldest, which is the direction the
specification asks for and the opposite of a queue. After an incident, the records worth
reading are the recent ones.

Event numbers follow §7.14.1.1's reservation strategy: a *ceiling* is persisted before any
number below it is issued, so a restart resumes above everything ever handed out. Persisting
after the fact loses the last record's number on an unclean reboot and reuses it — and a
client that has already seen that number silently drops the new event as a duplicate.

Recording an event and *reporting* one are two things, and a device has to do both: the store
is the device's, so the reporting engine cannot see a record appear. A subscriber that marked
its event path urgent is told about it explicitly; one that did not receives the record on
whatever report comes next, which is what §8.5 asks for — non-urgent queueing "does not
automatically trigger a Report transaction".

Where the next report resumes is **not** the device's to work out. Each report leaves the
number it reached on the subscription, and marking it reported applies that. Asked for as a
parameter it is a number a device has no way to compute — a report is built path by path and
the position is reset between them — and the answer every caller reaches for is zero, which
re-sends the subscriber's whole event history on every report for the life of the
subscription.

## The Timed transaction window

Some actions must not be replayable at a time of the attacker's choosing — a door unlock,
opening a commissioning window, an access-control entry. The answer is the `T` quality plus a
two-phase commit with a clock on it:

```text
Timed Request (Timeout = 1000 ms)  ──▶
                                   ◀──  Status Response (SUCCESS)   ← the clock starts here
Invoke Request  (TimedRequest=true)──▶   … within 1000 ms, or TIMEOUT
```

The `T` quality decides whether an element *requires* this. A separate window table decides
whether there *is* one, keyed by session and exchange. Three details are load-bearing:

- **The clock starts when the status response is sent, not when the request arrives.**
  Starting it on receipt charges the client for the server's processing time, which on a busy
  node is the difference between a 100 ms timeout working and not.
- **The window is consumed by the request that arrives on it**, including one it refuses.
  Leave it open and a single Timed Request pays for a second command later.
- **`TIMEOUT` and `TIMED_REQUEST_MISMATCH` stay distinct**, and expiry is checked first. One
  means "retry with a longer timeout", the other means "your client has a bug". Both were
  `UNSUPPORTED_ACCESS` before Matter 1.4.

## A version per cluster, or the report is discarded

§7.10.3 asks for one number per cluster instance: random when first published, incremented
whenever any attribute changes. A client keeps it and sends it back in a `DataVersionFilter`, and
the server skips everything that has not moved.

§10.6.4.1 says a report *may* omit it. The CHIP SDK disagrees in practice — its cluster-state
cache is keyed by version, and an attribute that arrives without one is parsed and then dropped.
The symptom is a commissioner that asks for `BasicCommissioningInfo`, `VendorID` and half a dozen
others, receives every one of them, and then reports each as *Key not found*. So a device that
omits them is spec-legal and impossible to commission.

```rust,ignore
let versions = DataVersions::<16>::new(rng.next_u32()?);
let server = Server::new(node, &acl, &clusters, 24).with_data_versions(&versions);

// A cluster that changes on its own — a sensor, a button — says so; writes arriving over the
// wire are bumped by the server.
versions.touch(endpoint, cluster);
```

A cluster that tracks its own version through `ClusterHandler::data_version` still wins: it knows
when its data changed, and the table only knows about writes that came in over the wire.

## One entry point, so the rules are not optional

The Timed window is one of several rules that sit between reading an opcode and doing any
work. `Dispatcher` owns them, so a node does not re-derive them from the specification in a
`match` statement:

```rust,ignore
let mut dispatcher: Dispatcher<4> = Dispatcher::new(product.max_paths_per_invoke);

match dispatcher.dispatch(&server, request, &ctx, &mut cursor, &mut scratch, &mut buf)? {
    Served::Reply { opcode, len, more_chunks } => send(opcode, &buf[..len]),
    Served::Subscribe(request) => subscriptions.accept(request)?,
    Served::Silent => {}
    Served::Unhandled { opcode } => { /* a response on an exchange this node opened */ }
}
```

| Refused before any work | Section | Answer |
|---|---|---|
| the Timed window expired | §8.7.2.3, §8.8.2.3 rule 1 | `TIMEOUT` |
| the window and the request's `TimedRequest` flag disagree, either way | rules 2 and 3 | `TIMED_REQUEST_MISMATCH` |
| more commands than `MaxPathsPerInvoke` | §8.8.2.3 rule 4 | `INVALID_ACTION` |
| no room to record a `TimedRequest` | §8.7.3.2 | `BUSY` |

The third is the one worth naming. `MaxPathsPerInvoke` is a Basic Information attribute whose
default is 1, and it is the *only* bound a server has on how much work one invoke message can
ask of it. A node that advertises it and does not enforce it is both violating §8.8.2.3 and
accepting unbounded batches — and the refusal has to come before the first command runs, or a
client is told the batch failed by a device that already acted on half of it.

Choosing the response opcode is the other thing this removes. A `WriteResponse` sent under
`REPORT_DATA` is not something the write's own tests can catch.

## A report that does not fit is chunked

A UDP message may not exceed the 1280-octet IPv6 minimum MTU (Core §4.4.4), and a whole-node
wildcard read exceeds it on any real device. So a report is not one message; it is a series of
them, and the last one is the only one that does not set `MoreChunkedMessages`.

```rust,no_run
let mut cursor = ReadCursor::START;
while !cursor.is_done() {
    let (bytes, _) = server.serve_chunk(
        paths.iter().copied().map(Ok),
        &ctx, None, &mut cursor, &mut scratch, &mut buf,
    )?;
    send(bytes);
    // §10.2.3: "each data message requires a response before the next data message
    // can be sent" — await the StatusResponse before looping.
}
```

Three things about this are easy to get wrong, and all three are load-bearing:

- **`MoreChunkedMessages` is a promise, not a hint.** A message that sets it tells the client
  another is coming. A server that sets it and stops leaves the client waiting for a message
  that never arrives — which, from the client's side, is indistinguishable from a slow device.
  So the flag and the cursor are the same decision: `serve_chunk` sets the flag exactly when
  `cursor.is_done()` is false.

- **The boundary is a size, not a count.** One attribute may be two octets and the next a
  900-octet certificate, so no fixed number of reports per message is both safe and efficient.
  Each block is written and rolled back if it overruns
  (`TlvWriter::checkpoint`), which is what "maximally packing" in §10.2.3 requires.

- **It always terminates.** A list too large for any message is split per §10.6.4.3.1 — one
  block clearing the list, then one block per item with `ListIndex` null. A value that is too
  large and *not* a list is answered `RESOURCE_EXHAUSTED` for its own path, so the read moves
  on instead of retrying it forever.

`Server::serve` remains for reads known to be small; it is `serve_chunk` with a cursor thrown
away. Subscriptions chunk the same way, through `prime` and `report_chunk`, because a priming
report is a whole read of everything the subscription covers.

## Reading a chunked report back

A client is the other half of chunking, and the half where getting it wrong is silent. The
first `ReportData` of a chunked answer is perfectly well-formed: every path concrete, every
value decodable. Nothing about it says it is a fraction except `MoreChunkedMessages` — so a
client that ignores the flag holds a partial picture of the node and has no way to find out.

```rust,ignore
let mut assembler = ReportAssembler::<8192>::new();
loop {
    let report = ReportData::decode(receive()?)?;
    if assembler.push(&report)? { break; }
    // §10.2.3: "each data message requires a response before the next data message can
    // be sent" — the server is waiting for this.
    send(status_response()?);
}
for item in assembler.reports() { /* the whole answer */ }
```

The buffer is sized against *what you asked for*, not against a message: a chunked answer is
by definition larger than any single message, or it would not have been chunked. An answer
that overflows it is refused rather than truncated — half a report is not a smaller report.

## Atomic writes: several attributes, or none

Some attributes are only meaningful together. A thermostat's heating and cooling setpoints are
each legal alone and can contradict as a pair, so writing them one at a time means passing
through a state the device must either reject or briefly obey.

§7.15's answer is a three-stage flow — `AtomicRequest(BeginWrite)` claims a set of attributes,
ordinary writes then *pend*, and `CommitWrite` applies them together. `matter_kit::im::atomic`
holds the claim: §7.15.3's endpoint, cluster, writer, fabric and attribute set, plus the
timeout that stops a client which crashed mid-write from holding those attributes forever.

The **pending values** stay with the cluster, because only the cluster can do what §7.15.3
asks — evaluate "integrity checks … in the context of the pending values of all the attributes".

The rule that carries the whole mechanism is a negative one, and the server enforces it:

> If a server receives a Write Request for an attribute that is not associated with an Atomic
> Write State that is also associated with the client making the request, the server SHALL
> return the error code INVALID_IN_STATE.

An attribute with the Atomic quality is writable *only* inside a claim covering it. A server
that implemented `AtomicRequest` faithfully and still let an ordinary write through would have
built the machinery and left the door open beside it.

## Writing a list says *how*, not just *what*

A list may be larger than one message, so §10.6.4.3.1 lets a client send it as a series of
blocks. The blocks are told apart by the **path**, never by the data:

| Path | Meaning |
|---|---|
| `ListIndex` omitted | replace the whole list with this value (an empty array clears it) |
| `ListIndex` null | append this one item to the list |
| `ListIndex` = *n* | an error — "only allowed to be omitted or null" |

So the operation reaches the cluster as a `WriteOp` parameter rather than being guessed from
the bytes:

```rust,ignore
fn write(&self, resolved: &Resolved<'_>, data: &[u8], op: WriteOp, ctx: &InteractionContext<'_>)
    -> Result<(), Status>
{
    match op {
        WriteOp::Replace => self.list.replace(data)?,
        WriteOp::Append  => self.list.push(data)?,
    }
    Ok(())
}
```

It has to be a parameter because it is genuinely not derivable: a list *of* arrays, or a
replace whose new contents are a single struct, produce the same bytes either way. A cluster
left to guess picks "replace", and then keeps only the **last** item of every list written
item by item — answering `SUCCESS` to all of it, so nothing appears wrong. An access control
list is written exactly this way.

One related rule the server enforces rather than assumes: §10.7.6.2's "a Write Request action
that is part of a Timed Write Interaction SHALL NOT be chunked". The two mechanisms
contradict each other — a Timed window is consumed by the first request on it, so every later
chunk would be told `TIMED_REQUEST_MISMATCH` — so the action is refused once, up front.
