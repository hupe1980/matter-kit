//! Software Diagnostics, cluster `0x0034` (Core §11.13).
//!
//! > The Software Diagnostics Cluster attempts to centralize all metrics that are relevant to
//! > the software that may be running on a Node.
//!
//! Heap and stack, essentially — how much is free now and how little has ever been free. On
//! the kind of device this crate is built for, the second number is the one that matters: a
//! node with 32 KB of RAM does not run out of memory gradually, it runs out once, three weeks
//! after shipping, in a code path nobody was watching. `CurrentHeapHighWatermark` and
//! `StackFreeMinimum` are the record of how close it came.
//!
//! # A crate with no allocator still has something to report
//!
//! `matter-kit` is no-alloc, so nothing *here* has a heap. The metrics are the device's: a
//! node that runs an RTOS with a heap for its application reports that heap, and one that has
//! none reports nothing and declares neither attribute. Which is why every method of
//! [`SoftwareMetrics`] returns an `Option` and the absent case is
//! [`Status::UnsupportedAttribute`] rather than a zero — "0 bytes free" and "no heap" read the
//! same to a client and mean opposite things.

use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{
    AttributeId, ClusterHandler, ClusterId, CommandId, EventId, InteractionContext, Status,
    StatusIb,
};
use crate::tlv::{Tag, TlvWriter};

use super::Cluster;

/// `0x0034` (§11.13.3).
pub const ID: ClusterId = 0x0034;

/// The revision §11.13.1's table ends on.
pub const REVISION: u16 = 1;

/// `WTRMRK` (§11.13.4) — "Node makes available the metrics for high watermark related to
/// memory consumption".
pub const FEATURE_WATERMARKS: u32 = 1 << 0;

/// `ThreadMetrics` (§11.13.6.1) — `list[ThreadMetricsStruct]`, max 64, `RV C`.
pub const THREAD_METRICS: AttributeId = 0x0000;
/// `CurrentHeapFree` (§11.13.6.2) — `uint64`, `RV C`.
pub const CURRENT_HEAP_FREE: AttributeId = 0x0001;
/// `CurrentHeapUsed` (§11.13.6.3) — `uint64`, `RV C`.
pub const CURRENT_HEAP_USED: AttributeId = 0x0002;
/// `CurrentHeapHighWatermark` (§11.13.6.4) — `uint64`, `RV C`, `WTRMRK`.
pub const CURRENT_HEAP_HIGH_WATERMARK: AttributeId = 0x0003;

/// `ResetWatermarks` (§11.13.7.1) — Manage, `WTRMRK`.
pub const RESET_WATERMARKS: CommandId = 0x00;

/// `SoftwareFault` (§11.13.8.1) — INFO.
pub const SOFTWARE_FAULT: EventId = 0x00;

/// One entry of `ThreadMetrics` (§11.13.5.1) — a *software* thread, not a Thread network.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadMetrics<'a> {
    /// "a server-assigned per-thread unique ID that is constant for the duration of the
    /// thread. Efforts SHOULD be made to avoid reusing ID values when possible."
    pub id: u64,
    /// "a vendor defined name or prefix of the software thread", at most 8 octets.
    pub name: &'a str,
    /// Stack bytes not currently in use, or `None` to omit the optional field.
    pub stack_free_current: Option<u32>,
    /// The least that has been free "between the current time and this attribute being reset
    /// or initialized" — the number that says how close the thread came to overflowing.
    pub stack_free_minimum: Option<u32>,
    /// Bytes allocated to the thread's stack.
    pub stack_size: Option<u32>,
}

impl ThreadMetrics<'_> {
    fn encode(&self, w: &mut TlvWriter<'_>) -> crate::error::Result<()> {
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), self.id)?;
        if !self.name.is_empty() {
            w.utf8(Tag::Context(1), self.name)?;
        }
        if let Some(value) = self.stack_free_current {
            w.unsigned(Tag::Context(2), u64::from(value))?;
        }
        if let Some(value) = self.stack_free_minimum {
            w.unsigned(Tag::Context(3), u64::from(value))?;
        }
        if let Some(value) = self.stack_size {
            w.unsigned(Tag::Context(4), u64::from(value))?;
        }
        w.end_container()
    }
}

/// What the device's runtime knows about its own memory.
///
/// Every method returns `Option` and defaults to `None`, because §11.13.6 marks every
/// attribute optional and a node without a heap has nothing to say about one. Reporting zero
/// instead would be a device that looks permanently out of memory.
pub trait SoftwareMetrics {
    /// Each active software thread in turn (§11.13.6.1).
    fn thread_metrics(&self, emit: &mut dyn FnMut(&ThreadMetrics<'_>)) {
        let _ = emit;
    }

    /// Heap bytes free for allocation. "The effective amount MAY be smaller due to heap
    /// fragmentation or other reasons" — so this is an upper bound, not a promise.
    fn current_heap_free(&self) -> Option<u64> {
        None
    }

    /// Heap bytes currently in use.
    fn current_heap_used(&self) -> Option<u64> {
        None
    }

    /// The most heap that has ever been in use (§11.13.6.4). "This value SHALL only be reset
    /// upon a Node reboot or upon receiving of the ResetWatermarks command."
    fn current_heap_high_watermark(&self) -> Option<u64> {
        None
    }

    /// §11.13.7.1's `ResetWatermarks`.
    ///
    /// The specification is exact about what "reset" means, and it is not zero: "the server
    /// SHALL set the value of the CurrentHeapHighWatermark attribute to the value of the
    /// CurrentHeapUsed attribute", and each thread's `StackFreeMinimum` to its
    /// `StackFreeCurrent`. A watermark reset to zero would claim the node had once used no
    /// memory at all, and would then never rise again until usage exceeded the real peak.
    fn reset_watermarks(&self) {}
}

/// A node that reports no software metrics at all.
///
/// Correct for a `no_std`, no-alloc device with no application heap, which is what this crate
/// is built for — and a conformant Software Diagnostics cluster, since §11.13.6 makes every
/// attribute optional.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMetrics;

impl SoftwareMetrics for NoMetrics {}

/// The descriptor for an instance with these features.
///
/// Derived from the specification's own tables. §11.13.6 marks every attribute optional and
/// gates `CurrentHeapHighWatermark` and `ResetWatermarks` on `WTRMRK`, so what a device serves
/// is almost entirely its own choice — and a fixed list would make that choice for it.
///
/// Returns [`ErrorCode::InvalidArgument`](crate::ErrorCode) for a feature this revision does
/// not define.
pub fn conforming(
    features: u32,
    optional: &Optional<'_>,
) -> crate::error::Result<Conforming<4, 1, 0, 1>> {
    Conforming::new(
        &crate::clusters::generated::software_diagnostics::CLUSTER,
        features,
        optional,
    )
}

/// Everything §11.13.6 makes optional, for a runtime that reports all of it.
pub const ALL_OPTIONAL: Optional<'static> = Optional {
    attributes: &[
        THREAD_METRICS,
        CURRENT_HEAP_FREE,
        CURRENT_HEAP_USED,
        CURRENT_HEAP_HIGH_WATERMARK,
    ],
    commands: &[],
    events: &[SOFTWARE_FAULT],
};

/// The Software Diagnostics cluster (§11.13).
#[derive(Debug)]
pub struct SoftwareDiagnostics<'a, M: SoftwareMetrics> {
    metrics: &'a M,
    features: u32,
}

impl<'a, M: SoftwareMetrics> SoftwareDiagnostics<'a, M> {
    /// A cluster over a runtime's own metrics.
    #[must_use]
    pub const fn new(metrics: &'a M, features: u32) -> Self {
        Self { metrics, features }
    }

    const fn watermarks(&self) -> bool {
        self.features & FEATURE_WATERMARKS != 0
    }
}

impl<M: SoftwareMetrics> ClusterHandler for SoftwareDiagnostics<'_, M> {
    fn read(
        &self,
        resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        match resolved.attribute {
            THREAD_METRICS => {
                full(w.start_array(tag))?;
                let mut failure = false;
                self.metrics.thread_metrics(&mut |thread| {
                    failure |= thread.encode(w).is_err();
                });
                if failure {
                    return Err(Status::ResourceExhausted);
                }
                full(w.end_container())
            }
            CURRENT_HEAP_FREE => {
                let Some(value) = self.metrics.current_heap_free() else {
                    return Err(Status::UnsupportedAttribute);
                };
                full(w.unsigned(tag, value))
            }
            CURRENT_HEAP_USED => {
                let Some(value) = self.metrics.current_heap_used() else {
                    return Err(Status::UnsupportedAttribute);
                };
                full(w.unsigned(tag, value))
            }
            CURRENT_HEAP_HIGH_WATERMARK => {
                // §11.13.6's conformance column makes this one `WTRMRK` rather than `O`: the
                // feature bit is the promise that it exists, so serving it without declaring
                // the feature would contradict the `FeatureMap` a client read first.
                if !self.watermarks() {
                    return Err(Status::UnsupportedAttribute);
                }
                let Some(value) = self.metrics.current_heap_high_watermark() else {
                    return Err(Status::UnsupportedAttribute);
                };
                full(w.unsigned(tag, value))
            }
            _ => Err(Status::UnsupportedAttribute),
        }
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        _fields: Option<&[u8]>,
        _ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        if resolved.command.id != RESET_WATERMARKS {
            return Err(Status::UnsupportedCommand.into());
        }
        if !self.watermarks() {
            return Err(Status::UnsupportedCommand.into());
        }
        self.metrics.reset_watermarks();
        Ok(None)
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<M: SoftwareMetrics> Cluster for SoftwareDiagnostics<'_, M> {
    const ID: ClusterId = ID;
}
