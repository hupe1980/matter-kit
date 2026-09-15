+++
title = "Access control"
description = "Who may do what to which element: the ACL entry, the privilege granting algorithm, CASE Authenticated Tags, and why an empty list is a wildcard."
weight = 8
+++

Every interaction a commissioned node serves is checked against its Access Control List first.
Specification §6.6.6 gives the decision as a "Conceptual Access Control Privilege Granting
algorithm" and is unusually strict about it:

> Implementations of this algorithm SHALL have an identical outcome to the output of this
> conceptual algorithm.

So `matter_kit::acl` follows its pseudocode clause by clause rather than paraphrasing it.

## An entry is four filters and a grant

```rust,ignore
Entry {
    fabric_index: FabricIndex(1),
    privilege:    Privilege::Operate,
    auth_mode:    AuthMode::Case,
    subjects:     [NodeId(0x1234)],        // who
    targets:      [Target::endpoint(1)],   // what
}
```

Each of `subjects` and `targets` is a filter — and **empty means every**, not none:

> Subject must match, or be "wildcard" … Empty is wildcard, no match required

This is the single most dangerous sign to get backwards. Read as "matches nothing", the
broadest grant a list can express silently becomes a no-op, and a device that should be
controllable is inert. Read correctly but applied to the wrong field, a narrow grant becomes a
total one.

What a subject or target may *be* is bounded too, and `Acl::add` refuses an entry that breaks
it. §9.10.5.7 gives each `AuthMode` its own shape for a Subject ID — CASE takes a node id or a
valid CAT, Group takes a group id in the low sixteen bits — and §7.21.2's identifier tables
bound a target's cluster and device type, §7.19.2.27 its endpoint. An entry naming `0`, or
cluster `0xFFFF_FFFF`, is stored happily by a node that does not check and then matches nothing
for the life of the fabric: an administrator's mistake taking effect as silence.

## Nothing grants the commissioner

A factory-fresh node's ACL is empty (§9.10.6.1), so the first administrator has no entry to
match. §6.6.6.2 resolves that inside the algorithm rather than in the table:

> PASE commissioning channel implicitly grants administer privilege to commissioner

The grant exists only while the PASE session does. It cannot be read back, edited, or left
behind — and §6.6.2.1 requires that the table not even be able to express it: "ACL entries
with a PASE authentication mode SHALL NOT be explicitly added to the Access Control List."
`Acl::add` refuses one.

## CASE Authenticated Tags, and the direction that matters

A CAT is a group-like subject carried in a node's operational certificate. Its 32 bits are an
identifier and a **version**, and the comparison runs one way only:

> both are CAT with matching CAT ID and acceptable CAT version …
> `get_cat_version(isd_subject) >= get_cat_version(acl_subject)`

The entry names the *minimum* version; the presenting node must be at least that. That is what
makes revocation work at all: an administrator bumps the version, reissues certificates to the
nodes that keep access, and the ones left behind fall out on their next request. Reversed, a
removed node keeps its access forever and the mechanism silently does nothing.

## The cluster that holds the list is governed by it

§9.10.5.7 requires the Administer privilege "to observe and modify the Access Control Cluster
itself" — to *read* it as well as write it. A subject granted Operate can drive the device but
cannot enumerate who else has access, and cannot widen its own.

Writing the list is where two rules meet. `ACL` is a list, so §10.6.4.3.1's encoding applies:
an administrator sends an empty array to clear it, then one block per entry with `ListIndex`
null. A cluster that could not tell replace from append would keep only the last entry and
report `SUCCESS` for all of it — see [the data model](@/docs/data-model.md#writing-a-list-says-how-not-just-what).

And the list is fabric-scoped in both directions. An administrator on fabric 2 that could read
or overwrite fabric 1's entries could take the node away from whoever commissioned it.

## The one step you must not skip

`AddNOC` carries a `CaseAdminSubject`, and §11.18.6.8 step 7 requires the device to turn it
into an Access Control entry of an exactly specified shape:

```rust,ignore
// From the FabricChange::Added the Operational Credentials cluster reports. Through the
// *cluster*, so §9.10.9.1's AccessControlEntryChanged records it like any other change: this
// is the entry every other one on the fabric is granted by, and an audit trail that omits it
// omits the grant everything else derives from.
access_control.add_admin_for_fabric(index, NodeId(case_admin_subject), &ctx)?;
```

Before that entry exists, the commissioner's only standing is the implicit PASE grant — which
evaporates with the session. §11.18.6.8 is blunt about the consequence:

> Unless such an Access Control Entry is added atomically as described here, there would be no
> way for the caller on its given Fabric to eventually add another Access Control Entry for
> CASE authentication mode.

The failure has no symptom. The fabric is joined, the node advertises itself over DNS-SD,
`CommissioningComplete` succeeds — and the device is then permanently beyond anyone's reach.
`add_admin_for_fabric` exists so the entry cannot be built slightly wrong, and it rejects a
subject outside the operational and CAT ranges, which is §11.18.6.8's `InvalidAdminSubject`.

## Changes take effect immediately — including mid-message

> Updates to the Access Control Cluster SHALL take immediate effect in the Access Control
> system.

§6.6.4 means this literally: a write that narrows your entry governs the very next thing the
node decides. The check reads the live list, not a snapshot.

With one bound, and it is the bound that makes the `ACL` attribute usable at all. §10.6.4.3.1's
way of replacing a list is a series of blocks that all name the same attribute — the first
clearing it, the rest appending — and on this attribute the clearing block removes the
administrator entry you are administering *with*. So the **access decision is taken once per
path per action** and carried by the rest of that action's blocks. It cannot widen anything: it
reuses a grant checked against the list as it stood when the action began, and a refusal is
never carried.

Across *actions* nothing is carried, which is where §9.10.6.2's advice bites:

> Administrators SHOULD be careful to avoid inadvertently removing their own administrative
> access … an Administrator SHOULD change its own administrative access entry by updating the
> existing entry or by creating a new entry before removing the old entry, and SHOULD NOT
> remove the old entry before creating any new entry.

A write that clears the list and stops there leaves nobody able to write it again.

## Wiring it up

The `AccessControl` trait takes a path and a privilege and no subject, because the subject
belongs to the *session*, not the path — §6.6.6.1.3's Incoming Subject Descriptor is derived
once per message from session metadata, never from anything the message claimed. `AclAccess`
binds it:

```rust,ignore
// §6.6.6.3's derivation. `pending_fabric` is the one AddNOC created and the fail-safe
// has not yet committed, if any.
let subject = SubjectDescriptor::from_session(&session, pending_fabric);
let access  = AclAccess::new(&acl, node, &subject);
let server  = Server::new(node, &access, &handler, limit);
```

`from_session` is the whole of §6.6.6.3, and the reason it takes a session rather than a
message header is the reason the section exists: a source node id in a header is whatever the
sender wrote, while the id in a session context is what CASE *proved*. It also carries the
peer's CASE Authenticated Tags, which is why they are kept on the session — the certificate
that proved them is long gone by the time an interaction arrives, and a subject without them
would match no CAT entry at all.

Three outcomes are worth knowing:

| Session | Result |
|---|---|
| PASE | `IsCommissioning` true, subject is passcode id 0, fabric may be 0 |
| CASE | node id plus every CAT; `IsCommissioning` true only on the *pending* fabric |
| CASE with no fabric | **unauthenticated** — grants nothing |

That last row is a deliberate distinction. §6.6.6.3 asserts a CASE session's fabric "cannot be
zero", and a descriptor that carried fabric 0 anyway would merely fail to match every entry —
which looks exactly like a correct denial. Returning the "no auth" descriptor says what
actually happened.

## It governs subscriptions too, for as long as they live

A subscription is established once and reports for hours. Resolving the privilege at subscribe
time and caching it would mean an administrator's revocation revoked nothing: the subscription
would keep delivering the node's state to a subject with no standing left, and the subscriber
would have no way to tell.

So every report re-runs the decision against the live list. Revoke a subject's entry and the
very next report carries no value — without the subscription being torn down, and with a
status rather than silence, so the client can tell "revoked" from "unchanged".

## What is not implemented

§6.6.2.8's Access Restriction List belongs to the ManagedDevice feature and is not built, so
`Outcome::Restricted` is never returned — inventing a restriction would deny access the
specification grants. The `Extension` attribute (the `EXTS` feature) and `AuxiliaryACL` are
likewise not served.
