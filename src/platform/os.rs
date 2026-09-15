//! The platform traits on an operating system, with no async runtime.
//!
//! This is what a Linux or macOS build gets: real UDP sockets, a real clock, the system
//! entropy source, and a file-backed key-value store. It deliberately does **not** depend
//! on Tokio or any other runtime — the futures here are driven by whatever executor the
//! consumer already has, including [`block_on`].
//!
//! The mechanism is a thread per blocking resource: a socket's receiver thread parks in
//! `recv_from` and wakes the task when a datagram lands; a timer's thread sleeps and wakes
//! the task when the deadline passes. That is not how a high-performance server is built —
//! it is how a *runtime-agnostic* platform is built without an epoll reactor of our own,
//! and a Matter node's socket count is measured in ones.
//!
//! A consumer with a runtime should implement the traits against it instead; that is a few
//! dozen lines and it is what `examples/` does for Embassy.

use std::collections::VecDeque;
use std::fs;
use std::future::Future;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Poll, Waker};

use super::{Clock, Granularity, Instant, KvStore, PeerAddr, Rng, Timer, Udp};
use crate::config::MAX_UDP_MESSAGE;
use crate::error::{Error, ErrorCode, Result};

fn platform_error(_: impl core::fmt::Debug) -> Error {
    Error::new(ErrorCode::Platform)
}

// --- Time ---------------------------------------------------------------------------

/// The system's monotonic clock, and sleeping on it.
///
/// [`Timer::now`] is measured from the first `StdTimer` created in the process, so the
/// numbers in a log stay small and comparable.
#[derive(Debug, Clone)]
pub struct StdTimer {
    origin: std::time::Instant,
}

impl Default for StdTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl StdTimer {
    /// Starts a timeline at this moment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

impl Timer for StdTimer {
    fn now(&self) -> Instant {
        Instant::from_micros(u64::try_from(self.origin.elapsed().as_micros()).unwrap_or(u64::MAX))
    }

    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        let origin = self.origin;
        // One thread per sleep, started at the first poll that is not already due.
        let mut started = false;
        core::future::poll_fn(move |cx| {
            let now = Instant::from_micros(
                u64::try_from(origin.elapsed().as_micros()).unwrap_or(u64::MAX),
            );
            if deadline.is_elapsed_at(now) {
                return Poll::Ready(());
            }
            if !started {
                started = true;
                let remaining = deadline.saturating_duration_since(now);
                let waker = cx.waker().clone();
                let _ = std::thread::Builder::new()
                    .name("matter-kit-timer".into())
                    .spawn(move || {
                        std::thread::sleep(std::time::Duration::from_micros(remaining.as_micros()));
                        waker.wake();
                    });
            }
            Poll::Pending
        })
    }
}

/// The system wall clock, in the Matter epoch.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdClock;

/// Seconds between the Unix epoch (1970-01-01) and the Matter epoch (2000-01-01).
const UNIX_TO_MATTER_EPOCH_SECS: u64 = 946_684_800;

impl Clock for StdClock {
    fn utc(&self) -> Option<u64> {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        let secs = unix.as_secs().checked_sub(UNIX_TO_MATTER_EPOCH_SECS)?;
        secs.checked_mul(1_000_000)
            .and_then(|us| us.checked_add(u64::from(unix.subsec_micros())))
    }

    fn granularity(&self) -> Granularity {
        Granularity::MicrosecondsGranularity
    }
}

// --- Randomness ---------------------------------------------------------------------

/// The operating system's entropy source.
///
/// Reads `/dev/urandom`, which on every platform this module builds for is a
/// cryptographically secure generator seeded by the kernel. A short read is an error, not
/// a partially-filled buffer: a nonce that is half predictable is not a nonce.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdRng;

impl Rng for StdRng {
    fn fill(&self, out: &mut [u8]) -> Result<()> {
        let mut f = fs::File::open("/dev/urandom").map_err(platform_error)?;
        f.read_exact(out).map_err(platform_error)
    }
}

// --- UDP ----------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Inbox {
    queue: VecDeque<(Vec<u8>, PeerAddr)>,
    waker: Option<Waker>,
    failed: bool,
}

/// An IPv6 UDP socket, with a receiver thread behind it.
#[derive(Debug)]
pub struct StdUdp {
    socket: Arc<UdpSocket>,
    inbox: Arc<Mutex<Inbox>>,
    stop: Arc<AtomicBool>,
}

impl StdUdp {
    /// Binds to `port` on every IPv6 interface, and starts receiving.
    ///
    /// Pass [`crate::PORT`] for an operational node; pass 0 to let the system choose,
    /// which is what a commissioner and every test wants.
    pub fn bind(port: u16) -> Result<Self> {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
        let socket = UdpSocket::bind(addr).map_err(platform_error)?;
        Self::from_socket(socket)
    }

    /// Takes over an already-bound socket.
    pub fn from_socket(socket: UdpSocket) -> Result<Self> {
        let socket = Arc::new(socket);
        let inbox = Arc::new(Mutex::new(Inbox::default()));
        let stop = Arc::new(AtomicBool::new(false));

        // A read timeout so the thread notices `stop` rather than parking forever.
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .map_err(platform_error)?;

        let rx_socket = Arc::clone(&socket);
        let rx_inbox = Arc::clone(&inbox);
        let rx_stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("matter-kit-udp".into())
            .spawn(move || {
                let mut buf = [0u8; MAX_UDP_MESSAGE];
                while !rx_stop.load(Ordering::Relaxed) {
                    match rx_socket.recv_from(&mut buf) {
                        Ok((n, from)) => {
                            let Some(data) = buf.get(..n) else { continue };
                            let Ok(mut inbox) = rx_inbox.lock() else {
                                return;
                            };
                            inbox.queue.push_back((data.to_vec(), to_peer(from)));
                            if let Some(w) = inbox.waker.take() {
                                w.wake();
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                ErrorKind::WouldBlock
                                    | ErrorKind::TimedOut
                                    | ErrorKind::Interrupted
                            ) => {}
                        Err(_) => {
                            let Ok(mut inbox) = rx_inbox.lock() else {
                                return;
                            };
                            inbox.failed = true;
                            if let Some(w) = inbox.waker.take() {
                                w.wake();
                            }
                            return;
                        }
                    }
                }
            })
            .map_err(platform_error)?;

        Ok(Self {
            socket,
            inbox,
            stop,
        })
    }

    /// The address the socket is bound to, which is how a test finds the port.
    pub fn local_addr(&self) -> Result<PeerAddr> {
        self.socket
            .local_addr()
            .map(to_peer)
            .map_err(platform_error)
    }
}

impl Drop for StdUdp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn to_peer(addr: SocketAddr) -> PeerAddr {
    match addr {
        SocketAddr::V6(v6) => PeerAddr {
            addr: v6.ip().octets(),
            port: v6.port(),
            scope_id: v6.scope_id(),
        },
        // Matter is IPv6-only operationally (Core §2.5.6); an IPv4 peer is mapped so it
        // is at least representable rather than silently becoming a different address.
        SocketAddr::V4(v4) => PeerAddr {
            addr: v4.ip().to_ipv6_mapped().octets(),
            port: v4.port(),
            scope_id: 0,
        },
    }
}

fn from_peer(addr: PeerAddr) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(addr.addr),
        addr.port,
        0,
        addr.scope_id,
    ))
}

impl Udp for StdUdp {
    fn recv_from(&self, buf: &mut [u8]) -> impl Future<Output = Result<(usize, PeerAddr)>> {
        core::future::poll_fn(move |cx| {
            let Ok(mut inbox) = self.inbox.lock() else {
                return Poll::Ready(Err(Error::new(ErrorCode::Platform)));
            };
            if inbox.failed {
                return Poll::Ready(Err(Error::new(ErrorCode::Platform)));
            }
            match inbox.queue.pop_front() {
                Some((data, from)) => {
                    let n = data.len().min(buf.len());
                    let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(..n)) else {
                        return Poll::Ready(Err(Error::new(ErrorCode::BufferTooSmall)));
                    };
                    dst.copy_from_slice(src);
                    Poll::Ready(Ok((n, from)))
                }
                None => {
                    inbox.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
    }

    fn send_to(&self, buf: &[u8], addr: PeerAddr) -> impl Future<Output = Result<()>> {
        let result = self
            .socket
            .send_to(buf, from_peer(addr))
            .map_err(platform_error)
            .and_then(|n| {
                if n == buf.len() {
                    Ok(())
                } else {
                    Err(Error::new(ErrorCode::Platform))
                }
            });
        core::future::ready(result)
    }

    fn join_multicast(&self, group: [u8; 16], scope_id: u32) -> Result<()> {
        self.socket
            .join_multicast_v6(&Ipv6Addr::from(group), scope_id)
            .map_err(platform_error)
    }

    fn leave_multicast(&self, group: [u8; 16], scope_id: u32) -> Result<()> {
        self.socket
            .leave_multicast_v6(&Ipv6Addr::from(group), scope_id)
            .map_err(platform_error)
    }
}

// --- Storage ------------------------------------------------------------------------

/// A key-value store as one file per key in a directory.
///
/// Writes go to a temporary file and are renamed into place, so a power cut leaves either
/// the old value or the new one and never half of either — which is the property the
/// fail-safe of Core §11.10 is built on.
#[derive(Debug, Clone)]
pub struct FileKv {
    root: PathBuf,
}

impl FileKv {
    /// Opens (and creates) a store rooted at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(platform_error)?;
        Ok(Self { root })
    }

    /// Maps a key to a file name in the root directory.
    ///
    /// Keys are hierarchical (`attrs/1/6`) but the store is flat: the whole key becomes
    /// one file name. The encoding is `[a-zA-Z0-9-]` verbatim and every other byte as
    /// `_XX` in hex, which has the two properties that matter.
    ///
    /// It is **injective**, so two different keys cannot land on one file — a mapping
    /// that turned both `a.b` and `a/b` into `a%b` would silently alias two fabrics.
    ///
    /// And it can never produce `.`, `..`, a separator or the empty string, so a key
    /// cannot escape the root no matter what it contains — an empty name would make the
    /// path the root directory itself. Keys come from this crate today, but a key that
    /// reaches a file path is exactly the sort of thing that later gets built out of
    /// something a peer said.
    fn path_of(&self, key: &str) -> PathBuf {
        // The leading `k` is what keeps the empty key from naming the root.
        let mut name = String::with_capacity(key.len().saturating_add(1));
        name.push('k');
        for b in key.as_bytes() {
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' => name.push(char::from(*b)),
                _ => {
                    name.push('_');
                    name.push(hex_digit(b >> 4));
                    name.push(hex_digit(b & 0x0f));
                }
            }
        }
        self.root.join(name)
    }
}

/// One lowercase hex digit for a nibble, for [`FileKv::path_of`].
///
/// Takes the low four bits itself, so there is no value of `nibble` for which this has no
/// answer — which is what lets it return a `char` rather than an `Option`.
const fn hex_digit(nibble: u8) -> char {
    match nibble & 0x0f {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

impl KvStore for FileKv {
    fn get(&self, key: &str, out: &mut [u8]) -> impl Future<Output = Result<Option<usize>>> {
        let result = match fs::read(self.path_of(key)) {
            Ok(data) => match out.get_mut(..data.len()) {
                Some(dst) => {
                    dst.copy_from_slice(&data);
                    Ok(Some(data.len()))
                }
                None => Err(Error::new(ErrorCode::BufferTooSmall)),
            },
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(platform_error(e)),
        };
        core::future::ready(result)
    }

    fn set(&self, key: &str, value: &[u8]) -> impl Future<Output = Result<()>> {
        let path = self.path_of(key);
        let result = (|| {
            let tmp = path.with_extension("tmp");
            let mut f = fs::File::create(&tmp).map_err(platform_error)?;
            f.write_all(value).map_err(platform_error)?;
            f.sync_all().map_err(platform_error)?;
            fs::rename(&tmp, &path).map_err(platform_error)
        })();
        core::future::ready(result)
    }

    fn remove(&self, key: &str) -> impl Future<Output = Result<()>> {
        let result = match fs::remove_file(self.path_of(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(platform_error(e)),
        };
        core::future::ready(result)
    }

    fn remove_prefix(&self, prefix: &str) -> impl Future<Output = Result<()>> {
        let encoded = self.path_of(prefix);
        let Some(encoded) = encoded.file_name().and_then(|s| s.to_str()) else {
            return core::future::ready(Err(Error::new(ErrorCode::InvalidArgument)));
        };
        let result = (|| {
            let entries = fs::read_dir(&self.root).map_err(platform_error)?;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with(encoded) {
                    let _ = fs::remove_file(entry.path());
                }
            }
            Ok(())
        })();
        core::future::ready(result)
    }
}

// --- Executor -----------------------------------------------------------------------

/// Runs a future to completion on the current thread, parking between wakeups.
///
/// A consumer with a runtime uses theirs; this is for tests, examples and small daemons
/// that would rather not take a dependency for one `block_on`.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    struct Park {
        awake: Mutex<bool>,
        condvar: Condvar,
    }

    impl std::task::Wake for Park {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            if let Ok(mut awake) = self.awake.lock() {
                *awake = true;
                self.condvar.notify_one();
            }
        }
    }

    let park = Arc::new(Park {
        awake: Mutex::new(false),
        condvar: Condvar::new(),
    });
    let waker = Waker::from(Arc::clone(&park));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut fut = core::pin::pin!(fut);

    'outer: loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        let Ok(mut awake) = park.awake.lock() else {
            // A poisoned lock cannot be recovered from here; go round and poll again so
            // the future's own error handling gets a chance rather than aborting.
            continue;
        };
        while !*awake {
            match park.condvar.wait(awake) {
                Ok(next) => awake = next,
                // The wait failed; fall back to polling, which is always safe. The guard
                // is gone with the failed wait, so there is nothing to reset here.
                Err(_) => continue 'outer,
            }
        }
        // `awake` is still held from the wait; reset it through that guard rather than
        // locking again, which would deadlock on a non-reentrant mutex.
        *awake = false;
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::platform::Duration;

    #[test]
    fn udp_round_trips_on_loopback() {
        let a = StdUdp::bind(0).expect("bind a");
        let b = StdUdp::bind(0).expect("bind b");
        let mut b_addr = b.local_addr().expect("addr");
        b_addr.addr = Ipv6Addr::LOCALHOST.octets();

        block_on(async {
            a.send_to(b"matter", b_addr).await.expect("send");
            let mut buf = [0u8; 64];
            let (n, _from) = b.recv_from(&mut buf).await.expect("recv");
            assert_eq!(&buf[..n], b"matter");
        });
    }

    #[test]
    fn the_timer_sleeps_about_the_right_amount() {
        let t = StdTimer::new();
        let start = t.now();
        block_on(t.sleep(Duration::from_millis(20)));
        let slept = t.now().saturating_duration_since(start);
        assert!(slept >= Duration::from_millis(20), "slept {slept:?}");
        assert!(slept < Duration::from_secs(2), "slept {slept:?}");
    }

    #[test]
    fn the_clock_is_in_the_matter_epoch() {
        let utc = StdClock.utc().expect("a clock");
        // 2020-01-01 in the Matter epoch; any real clock is past it and short of 2100.
        assert!(utc > 631_152_000_000_000, "{utc}");
        assert!(utc < 3_155_760_000_000_000, "{utc}");
    }

    #[test]
    fn random_bytes_differ() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        StdRng.fill(&mut a).expect("entropy");
        StdRng.fill(&mut b).expect("entropy");
        assert_ne!(a, b);
    }

    #[test]
    fn the_file_store_round_trips_and_isolates_keys() {
        let dir = std::env::temp_dir().join(std::format!("matter-kit-kv-{}", std::process::id()));
        let kv = FileKv::open(&dir).expect("open");
        block_on(async {
            let mut buf = [0u8; 64];
            assert_eq!(kv.get("fabrics", &mut buf).await.expect("get"), None);
            kv.set("fabrics", b"abc").await.expect("set");
            assert_eq!(kv.get("fabrics", &mut buf).await.expect("get"), Some(3));
            assert_eq!(&buf[..3], b"abc");

            kv.set("app/one", b"1").await.expect("set");
            kv.set("app/two", b"2").await.expect("set");
            kv.remove_prefix("app/").await.expect("remove_prefix");
            assert_eq!(kv.get("app/one", &mut buf).await.expect("get"), None);
            assert_eq!(kv.get("fabrics", &mut buf).await.expect("get"), Some(3));
        });
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_cannot_escape_the_root() {
        let dir = std::env::temp_dir().join("matter-kit-kv-escape");
        let kv = FileKv::open(&dir).expect("open");
        for key in ["../../etc/passwd", "..", ".", "/", "a/../b", ""] {
            let path = kv.path_of(key);
            assert!(path.starts_with(&dir), "{key:?} -> {path:?}");
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            assert!(!name.contains('.'), "{key:?} -> {name}");
            assert!(!name.contains('/'), "{key:?} -> {name}");
            assert_eq!(path.parent(), Some(dir.as_path()), "{key:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn distinct_keys_get_distinct_files() {
        // The first cut mapped every non-alphanumeric byte to `%`, so `a.b` and `a/b`
        // became the same file and two different fabrics shared one blob.
        let dir = std::env::temp_dir().join("matter-kit-kv-injective");
        let kv = FileKv::open(&dir).expect("open");
        let keys = ["a.b", "a/b", "a_b", "a-b", "attrs/1/6", "attrs/1_6"];
        for (i, a) in keys.iter().enumerate() {
            for b in keys.iter().skip(i + 1) {
                assert_ne!(kv.path_of(a), kv.path_of(b), "{a} and {b} collide");
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
