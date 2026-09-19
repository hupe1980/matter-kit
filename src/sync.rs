//! Shared state for a controller that runs on more than one thread.
//!
//! The crate is single-threaded by construction, and that splits it in two. A *device* is one
//! event loop, one `RefCell` per piece of state, and no atomics an MCU would have to pay for.
//! A *controller* on a multi-threaded runtime is none of those things: it drives many nodes
//! from a work-stealing pool, and a future that is `!Send` cannot be spawned there at all.
//!
//! [`Shared`] is the seam. Without the `sync-mutex` feature it is a [`core::cell::RefCell`] and the
//! controller stays single-threaded and cheap; with it, an [`RwLock`](std::sync::RwLock), and the
//! state becomes `Send + Sync` so a run future holding it can be spawned across threads.
//!
//! ```rust,ignore
//! use matter_kit::sync::Shared;
//!
//! let fabrics = Shared::new(FabricTable::new());
//! // The same two lines compile either way.
//! let count = fabrics.borrow().len();
//! fabrics.borrow_mut().remove(index);
//! ```
//!
//! # One rule, and it is not optional
//!
//! **Never hold a borrow across an `await`.**
//!
//! That is the whole of it, in both builds, because [`RwLock`](std::sync::RwLock) is the shape
//! [`RefCell`](core::cell::RefCell) already has: many shared borrows, or one exclusive borrow. A
//! [`Mutex`](std::sync::Mutex) would have one kind of lock, so two `borrow()`s would compile and
//! work without the feature and deadlock with it — and a seam whose two builds disagree about
//! what is legal is a seam that tests one of them.
//!
//! What differs between the builds is only what happens when the rule is broken: a `RefCell`
//! panics at the mistake, a lock waits somewhere else. Which is why the single-threaded build is
//! the one to develop against.
//!
//! The crate's own device clusters deliberately keep their [`core::cell::RefCell`]s: a device is
//! single-threaded by construction and converting them would trade a panic that points at the
//! mistake for a deadlock that does not.

#[cfg(not(feature = "sync-mutex"))]
use core::cell::RefCell;

/// State shared between the parts of a controller.
///
/// A [`core::cell::RefCell`] by default; an [`RwLock`](std::sync::RwLock) under `sync-mutex`.
/// Both admit many readers or one writer, so code written against one is correct on the other.
#[cfg(not(feature = "sync-mutex"))]
#[derive(Debug, Default)]
pub struct Shared<T>(RefCell<T>);

/// State shared between the parts of a controller, across threads.
#[cfg(feature = "sync-mutex")]
#[derive(Debug, Default)]
pub struct Shared<T>(std::sync::RwLock<T>);

/// A shared borrow of the contents.
#[cfg(not(feature = "sync-mutex"))]
pub type Ref<'a, T> = core::cell::Ref<'a, T>;

/// A shared borrow of the contents.
///
/// A read guard under `sync-mutex`, so several may be live at once — the same rule
/// [`core::cell::Ref`] follows.
#[cfg(feature = "sync-mutex")]
pub type Ref<'a, T> = std::sync::RwLockReadGuard<'a, T>;

/// An exclusive borrow of the contents.
#[cfg(not(feature = "sync-mutex"))]
pub type RefMut<'a, T> = core::cell::RefMut<'a, T>;

/// An exclusive borrow of the contents.
#[cfg(feature = "sync-mutex")]
pub type RefMut<'a, T> = std::sync::RwLockWriteGuard<'a, T>;

impl<T> Shared<T> {
    /// Wraps `value`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        #[cfg(not(feature = "sync-mutex"))]
        {
            Self(RefCell::new(value))
        }
        #[cfg(feature = "sync-mutex")]
        {
            Self(std::sync::RwLock::new(value))
        }
    }

    /// Borrows the contents.
    ///
    /// # Panics
    ///
    /// Without `sync-mutex`, if a mutable borrow is live — [`core::cell::RefCell`]'s rule. With
    /// it, never: a poisoned lock is recovered from rather than propagated, because a controller
    /// that stopped answering every node because one task panicked would turn one fault into an
    /// outage.
    pub fn borrow(&self) -> Ref<'_, T> {
        #[cfg(not(feature = "sync-mutex"))]
        {
            self.0.borrow()
        }
        #[cfg(feature = "sync-mutex")]
        {
            self.0
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    /// Borrows the contents exclusively.
    ///
    /// # Panics
    ///
    /// The same rule as [`Shared::borrow`].
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        #[cfg(not(feature = "sync-mutex"))]
        {
            self.0.borrow_mut()
        }
        #[cfg(feature = "sync-mutex")]
        {
            self.0
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    /// Takes the contents out.
    pub fn into_inner(self) -> T {
        #[cfg(not(feature = "sync-mutex"))]
        {
            self.0.into_inner()
        }
        #[cfg(feature = "sync-mutex")]
        {
            self.0
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }
}

/// Asserts at compile time that a controller's own state can cross threads under `sync-mutex`.
///
/// Not a test: a test would run once, and this fails the *build* the moment somebody adds a
/// `Rc` or a `Cell` to one of these types. The claim is that the controller path is `Send`,
/// and a claim about types is best checked by the type checker.
#[cfg(all(feature = "sync-mutex", feature = "rustcrypto"))]
const _: () = {
    const fn assert_send<T: Send>() {}
    const fn assert_sync<T: Sync>() {}

    // The commissioning flow's state machine and the fabric's certificate authority: what a
    // controller spawns one of per node it is bringing up.
    assert_send::<crate::commissioning::commissioner::Commissioner>();
    assert_send::<crate::ca::CertAuthority>();
    assert_sync::<crate::ca::CertAuthority>();
    // The client's half of a subscription — one per node a controller watches.
    assert_send::<crate::im::client::Subscription>();
    assert_sync::<crate::im::client::Subscription>();
    assert_send::<crate::im::client::ReportAssembler<1024>>();
    // And the seam itself, over anything that can cross a thread.
    assert_send::<Shared<u32>>();
    assert_sync::<Shared<u32>>();
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the backing type is chosen for: what compiles and works in the
    /// single-threaded build does the same thing in the multi-threaded one. A `Mutex` behind
    /// `Shared` would deadlock here under `sync-mutex` and pass without it.
    #[test]
    fn two_shared_borrows_are_live_at_once() {
        let shared = Shared::new(41u32);
        let first = shared.borrow();
        let second = shared.borrow();
        assert_eq!(*first + *second, 82);
    }

    #[test]
    fn an_exclusive_borrow_writes_through() {
        let shared = Shared::new(1u32);
        *shared.borrow_mut() = 7;
        assert_eq!(*shared.borrow(), 7);
        assert_eq!(shared.into_inner(), 7);
    }
}
