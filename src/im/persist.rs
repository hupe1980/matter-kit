//! Subscriptions that survive a reboot (Core §8.5).
//!
//! > An implementation MAY choose to persist the details of a subscription across reboots, but
//! > it is not necessary.
//!
//! Optional, then — and for a mains-powered device it hardly matters, because a subscriber
//! notices the silence within one maximum interval and re-subscribes. For an
//! [ICD](crate::icd) it matters a great deal: re-subscribing requires the device to be awake
//! and reachable, and a sleepy device is neither. A door sensor that forgot its subscriptions
//! on every power cut would need its clients to catch it during an active window to get them
//! back.
//!
//! # What survives, and what must not
//!
//! A subscription is partly durable facts and partly live state, and restoring the second kind
//! is worse than losing it:
//!
//! | Kept | Dropped |
//! |---|---|
//! | the id, so a subscriber's cached `SubscriptionId` still means something | the `SessionId` — §4.13 sessions do not outlive a reboot, and a restored one would point at whatever session took that number next |
//! | the fabric and the subscriber's Node ID, which is how it is found again | `last_report`, because the clock restarted at zero |
//! | the paths and the negotiated intervals | the dirty set, which is replaced by a full re-prime |
//! | the event bookmark, since §7.14.1.1's event numbers *are* durable | |
//!
//! The re-prime is the rule that matters. While the device was off, anything could have
//! changed and it has no record of what — so the subscriber's twin is not stale in some
//! identified way, it is simply unknown. §8.5.3.4's priming report is the only honest answer,
//! and a restored subscription that reported deltas would leave the client permanently wrong
//! about every attribute that changed during the outage, with nothing to correct it.
//!
//! # Restoring does not resume
//!
//! A restored subscription has no session and cannot report. It becomes live when its
//! subscriber comes back and establishes a new CASE session, at which point
//! [`rebind`] attaches it — matched on **fabric and Node ID**, never on a session
//! id, because that is the identity CASE actually proves.

use heapless::Vec;

use crate::config::Config;
use crate::error::{Error, ErrorCode, Result, bail};
use crate::im::path::{AttributePath, EventPath};
use crate::im::subscription::{Subscription, SubscriptionTable};
use crate::msg::{FabricIndex, NodeId, SessionId};
use crate::platform::Instant;
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

/// `SubscriptionId`.
const TAG_ID: u8 = 0;
/// The accessing fabric index.
const TAG_FABRIC: u8 = 1;
/// The subscriber's operational Node ID.
const TAG_PEER: u8 = 2;
/// `FabricFiltered`.
const TAG_FABRIC_FILTERED: u8 = 3;
/// The negotiated minimum interval, in seconds.
const TAG_MIN_INTERVAL: u8 = 4;
/// The negotiated maximum interval, in seconds.
const TAG_MAX_INTERVAL: u8 = 5;
/// The event bookmark.
const TAG_EVENT_NUMBER: u8 = 6;
/// The attribute paths.
const TAG_PATHS: u8 = 7;
/// The event paths.
const TAG_EVENT_PATHS: u8 = 8;

/// Writes one subscription's durable half.
fn encode_one<const P: usize>(subscription: &Subscription<P>, w: &mut TlvWriter<'_>) -> Result<()> {
    w.start_structure(Tag::Anonymous)?;
    w.unsigned(Tag::Context(TAG_ID), u64::from(subscription.id))?;
    if let Some(fabric) = subscription.fabric_index {
        w.unsigned(Tag::Context(TAG_FABRIC), u64::from(fabric.0))?;
    }
    if let Some(peer) = subscription.peer_node_id {
        w.unsigned(Tag::Context(TAG_PEER), peer.0)?;
    }
    w.bool(
        Tag::Context(TAG_FABRIC_FILTERED),
        subscription.fabric_filtered,
    )?;
    w.unsigned(
        Tag::Context(TAG_MIN_INTERVAL),
        u64::from(subscription.min_interval_s),
    )?;
    w.unsigned(
        Tag::Context(TAG_MAX_INTERVAL),
        u64::from(subscription.max_interval_s),
    )?;
    w.unsigned(
        Tag::Context(TAG_EVENT_NUMBER),
        subscription.next_event_number,
    )?;
    w.start_array(Tag::Context(TAG_PATHS))?;
    for path in &subscription.paths {
        path.encode(w, Tag::Anonymous)?;
    }
    w.end_container()?;
    w.start_array(Tag::Context(TAG_EVENT_PATHS))?;
    for path in &subscription.event_paths {
        path.encode(w, Tag::Anonymous)?;
    }
    w.end_container()?;
    w.end_container()
}

/// Writes every subscription worth keeping, as one TLV array.
///
/// A subscription with no accessing fabric is **skipped**: it was made over PASE, during
/// commissioning, and §2.11.2.2 allows it only "subject to available resources". There is
/// nothing on the far side of a reboot for it to belong to — the PASE session is gone and the
/// commissioner has moved on to CASE — so persisting it would restore a subscription that can
/// never be rebound and never be reported to, holding one of a device's few slots forever.
///
/// Returns how many were written.
pub fn save<C: Config, const N: usize, const P: usize>(
    table: &SubscriptionTable<C, N, P>,
    w: &mut TlvWriter<'_>,
    tag: Tag,
) -> Result<usize> {
    w.start_array(tag)?;
    let mut kept = 0usize;
    for subscription in table.iter() {
        if subscription.fabric_index.is_none() || subscription.peer_node_id.is_none() {
            continue;
        }
        encode_one(subscription, w)?;
        kept = kept.saturating_add(1);
    }
    w.end_container()?;
    Ok(kept)
}

/// A subscription's durable half — exactly what survives a reboot.
///
/// Naming it is the point. The fields a subscription has and this does not are the ones whose
/// restoration would be *worse* than their loss, and a type that listed all of them would let
/// one be carried across by accident.
#[derive(Debug, Clone)]
pub struct Durable<const P: usize> {
    /// `SubscriptionId`, kept so a subscriber's cached id still means what it meant.
    pub id: u32,
    /// The accessing fabric.
    pub fabric_index: FabricIndex,
    /// The subscriber's operational Node ID — how it is found again.
    pub peer_node_id: NodeId,
    /// `FabricFiltered`, which "SHALL remain in effect for all data reported".
    pub fabric_filtered: bool,
    /// The negotiated minimum interval, in seconds.
    pub min_interval_s: u16,
    /// The negotiated maximum interval, in seconds.
    pub max_interval_s: u16,
    /// The event bookmark. §7.14.1.1's event numbers are themselves durable, so this is
    /// meaningful on the far side of a reboot in a way that a timestamp is not.
    pub next_event_number: u64,
    /// The subscribed attribute paths, still as wildcards where they were wildcards.
    pub paths: Vec<AttributePath, P>,
    /// The subscribed event paths.
    pub event_paths: Vec<EventPath, P>,
}

/// Narrows a stored `u64` to the type its field was written from.
fn narrow<T: TryFrom<u64>>(value: u64) -> Result<T> {
    T::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}

/// Reads one subscription whose opening structure the caller has taken.
fn decode_one<const P: usize>(reader: &mut TlvReader<'_>) -> Result<Durable<P>> {
    let mut id = None;
    let mut fabric_index = None;
    let mut peer_node_id = None;
    let mut fabric_filtered = false;
    let mut min_interval_s = 0u16;
    let mut max_interval_s = 0u16;
    let mut next_event_number = 0u64;
    let mut paths: Vec<AttributePath, P> = Vec::new();
    let mut event_paths: Vec<EventPath, P> = Vec::new();

    loop {
        let Some(field) = reader.next_element()? else {
            bail!(TlvTruncated)
        };
        if field.value == Value::EndOfContainer {
            break;
        }
        match field.tag.context() {
            // A value too wide for its field is `TlvOutOfRange`, not a truncation: persisted
            // state that no longer fits the type it was written from is a damaged store.
            Some(TAG_ID) => id = Some(narrow::<u32>(field.unsigned()?)?),
            Some(TAG_FABRIC) => {
                fabric_index = Some(FabricIndex(narrow::<u8>(field.unsigned()?)?));
            }
            Some(TAG_PEER) => peer_node_id = Some(NodeId(field.unsigned()?)),
            Some(TAG_FABRIC_FILTERED) => fabric_filtered = field.bool()?,
            Some(TAG_MIN_INTERVAL) => min_interval_s = narrow::<u16>(field.unsigned()?)?,
            Some(TAG_MAX_INTERVAL) => max_interval_s = narrow::<u16>(field.unsigned()?)?,
            Some(TAG_EVENT_NUMBER) => next_event_number = field.unsigned()?,
            Some(TAG_PATHS) => {
                if field.value.container() != Some(ContainerKind::Array) {
                    bail!(TlvWrongType)
                }
                loop {
                    let Some(item) = reader.next_element()? else {
                        bail!(TlvTruncated)
                    };
                    if item.value == Value::EndOfContainer {
                        break;
                    }
                    paths
                        .push(AttributePath::decode(reader)?)
                        .map_err(|_| Error::new(ErrorCode::NoSpace))?;
                }
            }
            Some(TAG_EVENT_PATHS) => {
                if field.value.container() != Some(ContainerKind::Array) {
                    bail!(TlvWrongType)
                }
                loop {
                    let Some(item) = reader.next_element()? else {
                        bail!(TlvTruncated)
                    };
                    if item.value == Value::EndOfContainer {
                        break;
                    }
                    event_paths
                        .push(EventPath::decode(reader)?)
                        .map_err(|_| Error::new(ErrorCode::NoSpace))?;
                }
            }
            _ => reader.skip_value(&field)?,
        }
    }

    let (Some(id), Some(fabric_index), Some(peer_node_id)) = (id, fabric_index, peer_node_id)
    else {
        // `save` never writes a record without a fabric and a node id, because one could
        // never be rebound; a record missing either is damaged.
        bail!(TlvNotFound)
    };
    if paths.is_empty() && event_paths.is_empty() {
        // §8.5.2.2: "At least one attribute or event SHALL be indicated in the action." A
        // record with neither is corrupt, and restoring it would occupy a slot forever while
        // reporting nothing.
        bail!(InvalidArgument)
    }
    Ok(Durable {
        id,
        fabric_index,
        peer_node_id,
        fabric_filtered,
        min_interval_s,
        max_interval_s,
        next_event_number,
        paths,
        event_paths,
    })
}

/// Reads subscriptions back from what [`save`] wrote.
///
/// Restored subscriptions are inert: each carries no session, so
/// [`SubscriptionTable::due`](crate::im::SubscriptionTable::due) will not select it until
/// [`rebind`] has attached one. They are re-primed, so the first report each sends
/// carries every path in full.
///
/// A malformed record fails the whole restore rather than being skipped. Persisted state that
/// does not decode means the store is damaged, and a device that quietly kept the half it
/// could read would have subscriptions the client believes in and the device has forgotten —
/// which is exactly the failure persistence exists to prevent, arrived at more slowly.
pub fn restore<C: Config, const N: usize, const P: usize>(
    table: &mut SubscriptionTable<C, N, P>,
    bytes: &[u8],
    now: Instant,
) -> Result<usize> {
    let mut reader = TlvReader::new(bytes);
    let Some(head) = reader.next_element()? else {
        bail!(TlvTruncated)
    };
    if head.value.container() != Some(ContainerKind::Array) {
        bail!(TlvWrongType)
    }

    let mut restored = 0usize;
    loop {
        let Some(item) = reader.next_element()? else {
            bail!(TlvTruncated)
        };
        if item.value == Value::EndOfContainer {
            break;
        }
        if item.value.container() != Some(ContainerKind::Structure) {
            bail!(TlvWrongType)
        }
        let durable = decode_one::<P>(&mut reader)?;
        // §8.5.3.1's ids must stay unique, and a reused one points a subscriber's cached
        // `SubscriptionId` at somebody else's subscription.
        table.reserve_id(durable.id);
        table.insert_restored(durable, now)?;
        restored = restored.saturating_add(1);
    }
    Ok(restored)
}

/// Attaches restored subscriptions to a subscriber that has come back.
///
/// Matched on fabric and Node ID, which is what CASE proved, rather than on a session id,
/// which did not survive. Returns how many were bound.
///
/// Call it when a CASE session is established — a device that waited for the subscriber to
/// send something would wait forever, because from the subscriber's side the subscription is
/// already established and there is nothing left to send.
pub fn rebind<C: Config, const N: usize, const P: usize>(
    table: &mut SubscriptionTable<C, N, P>,
    fabric: FabricIndex,
    peer: NodeId,
    session: SessionId,
    now: Instant,
) -> usize {
    let mut bound = 0usize;
    for subscription in table.iter_mut() {
        if subscription.session.is_some()
            || subscription.fabric_index != Some(fabric)
            || subscription.peer_node_id != Some(peer)
        {
            continue;
        }
        subscription.session = Some(session);
        // The intervals start from the moment it became live, not from when it was restored:
        // a subscription that sat dormant for an hour must not fire the instant it is bound,
        // because §8.5.3.4's minimum interval is a promise to the subscriber about pacing.
        subscription.last_report = now;
        bound = bound.saturating_add(1);
    }
    bound
}
