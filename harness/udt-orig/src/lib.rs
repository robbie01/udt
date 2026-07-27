//! Blocking-mode bindings to **unmodified upstream UDT**, for regression-testing
//! the heavily-modified fork in `udt-compat`.
//!
//! # Why this crate exists
//!
//! `udt-compat/udt-sys/udt/` is a fork of <https://github.com/dorkbox/udt> with
//! substantial changes: `SOCK_STREAM` support stripped, `CGuard`/`CCondDelegate`
//! replaced with `std::mutex`/`std::condition_variable` plus a custom
//! `rsynch.h`, `epoll.cpp` and `md5.cpp` deleted in favour of a Rust readiness
//! poller, and **blocking mode removed entirely**. None of that was covered by
//! tests. This crate builds the upstream sources untouched so the Rust
//! implementation can be exercised against a known-good reference.
//!
//! # These two C++ builds must never meet
//!
//! Both this crate and `udt-compat/udt-sys` compile a full copy of UDT. Their
//! mangled C++ symbols are byte-identical (`CUDT`, `CUDTUnited`, `CSndBuffer`,
//! …), and the generated cxx shims collide too, since the shim name embeds the
//! cxx version rather than anything crate-specific. Linking both into one
//! binary is an ODR violation with two `CUDT::s_UDTUnited` singletons and two
//! independent `startup()`/`cleanup()` refcounts.
//!
//! What keeps this safe is the dependency graph, not luck: `udt-proto` and
//! `udt-async` are pure Rust and do not depend on `udt-sys`, so a test crate
//! that pulls in `udt-async` + `udt-orig` (and **not** `udt-compat`) links
//! exactly one copy. `tests/upstream-compat` is that crate, and it has a test
//! asserting the invariant. Do not add `udt-compat` to it, and do not add these
//! tests to `tests/integration`, which already depends on the fork.
//!
//! # Blocking only
//!
//! Upstream has no `rpoll`, so the async readiness path used by `udt-compat` is
//! unavailable here. Every call blocks the calling thread; callers should hoist
//! them onto `tokio::task::spawn_blocking` or a plain thread, and impose their
//! own deadline with `tokio::time::timeout` on the join.
//!
//! Deliberately **not** using `UDT_SNDTIMEO`/`UDT_RCVTIMEO` for that deadline.
//! Setting either switches upstream from `pthread_cond_wait` onto a
//! `pthread_cond_timedwait` path that does not wake promptly on data arrival —
//! it waits out the entire timeout, then breaks the connection. With a 20 s
//! timeout configured, a 200-message upstream-to-upstream transfer that should
//! take 0.12 s instead stalled and failed with ECONNLOST. Leave the UDT-level
//! timeouts at their infinite default and bound the wait from the Rust side.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use os_socketaddr::OsSocketAddr;

mod ffi;

pub use ffi::Socket as RawSocket;

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use winapi::shared::ws2def::{AF_INET, AF_INET6, SOCK_DGRAM};
    } else {
        use libc::{AF_INET, AF_INET6, SOCK_DGRAM};
    }
}

// ── Library lifecycle ────────────────────────────────────────────────────────

/// `UDT::startup()` / `cleanup()` are refcounted globally. Guarded by a mutex
/// because tests create endpoints from many threads at once.
static INSTANCES: Mutex<usize> = Mutex::new(0);

struct Instance;

impl Instance {
    fn acquire() -> Self {
        let mut n = INSTANCES.lock().unwrap();
        if *n == 0 {
            unsafe { ffi::startup() };
        }
        *n += 1;
        Instance
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let mut n = INSTANCES.lock().unwrap();
        *n -= 1;
        if *n == 0 {
            unsafe { ffi::cleanup() };
        }
    }
}

fn last_error() -> io::Error {
    let code = unsafe { ffi::getlasterror_code() };
    io::Error::other(format!("UDT error {code}"))
}

// ── Socket ───────────────────────────────────────────────────────────────────

struct Sock {
    _inst: Instance,
    raw: ffi::Socket,
}

impl Sock {
    fn new(af: i32) -> io::Result<Self> {
        let inst = Instance::acquire();
        let raw = unsafe { ffi::socket(af, SOCK_DGRAM, 0) };
        if raw == ffi::INVALID_SOCK {
            return Err(last_error());
        }
        let s = Sock { _inst: inst, raw };
        // Explicitly blocking. This is upstream's default, but state it so the
        // intent is visible — and see the module docs for why no UDT-level
        // timeout is set alongside it.
        s.set_bool(ffi::SocketOption::SendSyn, true)?;
        s.set_bool(ffi::SocketOption::RecvSyn, true)?;
        Ok(s)
    }

    fn set_bool(&self, opt: ffi::SocketOption, value: bool) -> io::Result<()> {
        let res = unsafe {
            ffi::setsockopt(
                self.raw,
                0,
                opt,
                (&raw const value).cast(),
                mem::size_of::<bool>() as i32,
            )
        };
        if res == -1 { Err(last_error()) } else { Ok(()) }
    }

    fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        let os: OsSocketAddr = addr.into();
        let res = unsafe { ffi::bind(self.raw, os.as_ptr().cast(), os.len() as i32) };
        if res == -1 { Err(last_error()) } else { Ok(()) }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let mut os = OsSocketAddr::new();
        let mut len = os.len() as i32;
        let res = unsafe { ffi::getsockname(self.raw, os.as_mut_ptr().cast(), &mut len) };
        if res == -1 {
            return Err(last_error());
        }
        os.into_addr()
            .ok_or_else(|| io::Error::other("getsockname returned an unusable address"))
    }
}

impl Drop for Sock {
    fn drop(&mut self) {
        unsafe { ffi::close(self.raw) };
    }
}

fn af_of(addr: SocketAddr) -> i32 {
    match addr {
        SocketAddr::V4(_) => AF_INET,
        SocketAddr::V6(_) => AF_INET6,
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// A bound address from which listeners and connections are created.
///
/// Mirrors `udt_compat::Endpoint` so the interop test scenarios port across
/// with minimal reshaping. Upstream UDT shares one UDP multiplexer between all
/// sockets bound to the same address, so the listener and connector sockets
/// created here reuse this endpoint's port.
pub struct Endpoint {
    binding: Sock,
}

impl Endpoint {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let binding = Sock::new(af_of(addr))?;
        binding.bind(addr)?;
        Ok(Endpoint { binding })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.binding.local_addr()
    }

    /// Start listening. Blocks in [`Listener::accept`].
    pub fn listen(&self, backlog: u32) -> io::Result<Listener> {
        let addr = self.binding.local_addr()?;
        let u = Sock::new(af_of(addr))?;
        u.bind(addr)?;
        let res = unsafe { ffi::listen(u.raw, backlog as i32) };
        if res == -1 {
            return Err(last_error());
        }
        Ok(Listener { u })
    }

    /// Connect to `addr`. **Blocks** until the handshake completes or times out.
    pub fn connect(&self, addr: SocketAddr, rendezvous: bool) -> io::Result<Connection> {
        let local = self.binding.local_addr()?;
        let u = Sock::new(af_of(local))?;
        u.bind(local)?;
        if rendezvous {
            u.set_bool(ffi::SocketOption::Rendezvous, true)?;
        }
        let os: OsSocketAddr = addr.into();
        let res = unsafe { ffi::connect(u.raw, os.as_ptr().cast(), os.len() as i32) };
        if res == -1 {
            return Err(last_error());
        }
        Ok(Connection { u })
    }
}

pub struct Listener {
    u: Sock,
}

impl Listener {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.u.local_addr()
    }

    /// **Blocks** until a peer connects.
    pub fn accept(&self) -> io::Result<Connection> {
        let inst = Instance::acquire();
        let raw = unsafe { ffi::accept(self.u.raw, std::ptr::null_mut(), std::ptr::null_mut()) };
        if raw == ffi::INVALID_SOCK {
            return Err(last_error());
        }
        Ok(Connection { u: Sock { _inst: inst, raw } })
    }
}

pub struct Connection {
    u: Sock,
}

impl Connection {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.u.local_addr()
    }

    /// Send one message. **Blocks** until it is buffered.
    ///
    /// `in_order = false` asks the peer to deliver this message ahead of earlier
    /// ones that are still in flight; `ttl` bounds how long it may be
    /// retransmitted. Both are exposed so the out-of-order and TTL paths can be
    /// exercised against upstream.
    pub fn send_with(&self, buf: &[u8], ttl: Option<Duration>, in_order: bool) -> io::Result<usize> {
        let res = unsafe {
            ffi::sendmsg(
                self.u.raw,
                buf.as_ptr().cast(),
                buf.len().try_into().unwrap_or(i32::MAX),
                ttl.map_or(-1, |t| t.as_millis().try_into().unwrap_or(i32::MAX)),
                in_order,
            )
        };
        if res == -1 {
            return Err(last_error());
        }
        Ok(res as usize)
    }

    /// Send one message, ordered and fully reliable.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.send_with(buf, None, true)
    }

    /// Receive one message. **Blocks** until one arrives.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let res = unsafe {
            ffi::recvmsg(
                self.u.raw,
                buf.as_mut_ptr().cast(),
                buf.len().try_into().unwrap_or(i32::MAX),
            )
        };
        if res == -1 {
            return Err(last_error());
        }
        Ok(res as usize)
    }
}
