//! Monotonic time, in the units the specification uses.
//!
//! Matter states its timings in milliseconds (MRP intervals, subscription intervals) and
//! in seconds (fail-safe, idle-mode duration), and its wall-clock times in microseconds
//! since the Matter epoch. Doing arithmetic across those in a `u32` is how off-by-1000
//! bugs happen, so there is one duration type, it is microseconds in a `u64`, and it
//! saturates rather than wraps.
//!
//! `u64` microseconds is about 584 000 years, so saturation is unreachable in practice —
//! but it is the behaviour a hostile peer's timing values should meet, rather than a
//! debug-build panic and a release-build wrap.

/// A span of time, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Duration(u64);

impl Duration {
    /// No time at all.
    pub const ZERO: Self = Self(0);

    /// The longest representable span, used as "never".
    pub const MAX: Self = Self(u64::MAX);

    /// From microseconds.
    #[must_use]
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// From milliseconds, saturating.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis.saturating_mul(1_000))
    }

    /// From seconds, saturating.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000))
    }

    /// As microseconds.
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// As whole milliseconds, rounding down.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0.wrapping_div(1_000)
    }

    /// As whole seconds, rounding down.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0.wrapping_div(1_000_000)
    }

    /// Addition that saturates instead of wrapping.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Subtraction that saturates at zero.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Multiplication by a scalar, saturating.
    #[must_use]
    pub const fn saturating_mul(self, factor: u64) -> Self {
        Self(self.0.saturating_mul(factor))
    }

    /// Multiplication by a rational `numerator / denominator`, saturating.
    ///
    /// MRP's backoff constants are rationals — a base of 1.6, a jitter of 0.25, a margin
    /// of 1.1 (Core §4.12.2.1) — and doing that in floating point on a microcontroller
    /// that has no FPU is both slow and needlessly imprecise. This is how the crate
    /// computes them.
    #[must_use]
    pub const fn mul_ratio(self, numerator: u64, denominator: u64) -> Self {
        // Split into whole and fractional parts to keep the product inside `u64` for the
        // spans Matter actually uses. `checked_div`/`checked_rem` rather than `/` and `%`
        // so a zero denominator is a value — `Duration::MAX`, i.e. "never" — instead of a
        // division trap.
        let (Some(whole), Some(rest)) = (
            self.0.checked_div(denominator),
            self.0.checked_rem(denominator),
        ) else {
            return Self::MAX;
        };
        let Some(fraction) = rest.saturating_mul(numerator).checked_div(denominator) else {
            return Self::MAX;
        };
        Self(whole.saturating_mul(numerator).saturating_add(fraction))
    }
}

/// A point on a monotonic timeline.
///
/// The origin is whatever the [`Timer`](super::Timer) chose; only differences are
/// meaningful. It never goes backwards and is unaffected by the wall clock changing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Instant(u64);

impl Instant {
    /// The timeline's origin.
    pub const ZERO: Self = Self(0);

    /// The furthest representable point, used as "never".
    pub const MAX: Self = Self(u64::MAX);

    /// From microseconds since the origin.
    #[must_use]
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// As microseconds since the origin.
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// As milliseconds since the origin — Core §7.19.2.7's `systime-ms`.
    ///
    /// Truncating, like every other reading of a coarser clock from a finer one. The
    /// specification's own use of it is a client correlating its clock with the node's
    /// (§11.12.7.3), where a sub-millisecond difference is below the jitter of the message
    /// carrying it.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0 / 1000
    }

    /// This instant plus a span, saturating.
    #[must_use]
    pub const fn saturating_add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.0))
    }

    /// This instant minus a span, saturating at the origin.
    #[must_use]
    pub const fn saturating_sub(self, d: Duration) -> Self {
        Self(self.0.saturating_sub(d.0))
    }

    /// How long from `earlier` to this instant; zero if this one is not later.
    #[must_use]
    pub const fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }

    /// Whether this instant has been reached at `now`.
    #[must_use]
    pub const fn is_elapsed_at(self, now: Self) -> bool {
        now.0 >= self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_conversions() {
        assert_eq!(Duration::from_millis(1).as_micros(), 1_000);
        assert_eq!(Duration::from_secs(1).as_millis(), 1_000);
        assert_eq!(Duration::from_micros(1_999).as_millis(), 1);
    }

    #[test]
    fn arithmetic_saturates_rather_than_wrapping() {
        assert_eq!(
            Duration::MAX.saturating_add(Duration::from_secs(1)),
            Duration::MAX
        );
        assert_eq!(
            Duration::ZERO.saturating_sub(Duration::from_secs(1)),
            Duration::ZERO
        );
        assert_eq!(Duration::MAX.saturating_mul(2), Duration::MAX);
        assert_eq!(
            Instant::MAX.saturating_add(Duration::from_secs(1)),
            Instant::MAX
        );
        assert_eq!(
            Instant::ZERO.saturating_sub(Duration::from_secs(1)),
            Instant::ZERO
        );
        // Saturating from_secs, so a hostile "seconds" value cannot wrap into a short one.
        assert_eq!(Duration::from_secs(u64::MAX), Duration::MAX);
    }

    #[test]
    fn mul_ratio_is_mrps_arithmetic() {
        // MRP_BACKOFF_BASE is 1.6 (Core §4.12.2.1).
        let base = Duration::from_millis(300);
        assert_eq!(base.mul_ratio(16, 10).as_millis(), 480);
        // 1.1 margin.
        assert_eq!(base.mul_ratio(11, 10).as_millis(), 330);
        // A quarter, for jitter.
        assert_eq!(base.mul_ratio(1, 4).as_millis(), 75);
        // Precision is kept for values that do not divide evenly.
        assert_eq!(Duration::from_micros(7).mul_ratio(16, 10).as_micros(), 11);
        // A zero denominator does not divide by zero.
        assert_eq!(base.mul_ratio(1, 0), Duration::MAX);
    }

    #[test]
    fn instants_order_and_subtract() {
        let a = Instant::from_micros(100);
        let b = Instant::from_micros(250);
        assert!(a < b);
        assert_eq!(b.saturating_duration_since(a), Duration::from_micros(150));
        assert_eq!(a.saturating_duration_since(b), Duration::ZERO);
        assert!(a.is_elapsed_at(b));
        assert!(!b.is_elapsed_at(a));
        assert!(
            a.is_elapsed_at(a),
            "a deadline is reached at its own instant"
        );
    }
}
