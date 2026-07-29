#![deny(unsafe_code)]

mod instance;
mod util;
use std::{io, mem, net::SocketAddr, ptr, sync::Arc, time::Duration};

use futures::FutureExt;
use instance::*;
use os_socketaddr::OsSocketAddr;
use tokio::task::spawn_blocking;
use udt_sys::INVALID_SOCK;
use util::*;

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use winapi::shared::ws2def::{AF_INET, AF_INET6, SOCK_DGRAM};
    } else {
        use libc::{AF_INET, AF_INET6, SOCK_DGRAM};
    }
}

#[derive(Debug)]
struct Socket {
    _inst: Instance,
    inner: udt_sys::Socket,
}

impl Socket {
    #[allow(unsafe_code)] // FFI into the C++ implementation
    fn local_addr_os(&self) -> io::Result<OsSocketAddr> {
        let mut addr = OsSocketAddr::new();
        let mut namelen = addr.len() as i32;
        let res =
            unsafe { udt_sys::getsockname(self.inner, addr.as_mut_ptr().cast(), &mut namelen) };
        if res == -1 {
            return Err(unsafe { udt_getlasterror() });
        }
        Ok(addr)
    }

    #[allow(unsafe_code)] // FFI into the C++ implementation
    fn peer_addr_os(&self) -> io::Result<OsSocketAddr> {
        let mut addr = OsSocketAddr::new();
        let mut namelen = addr.len() as i32;
        let res =
            unsafe { udt_sys::getpeername(self.inner, addr.as_mut_ptr().cast(), &mut namelen) };
        if res == -1 {
            return Err(unsafe { udt_getlasterror() });
        }
        Ok(addr)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr_os().map(|addr| addr.into_addr().unwrap())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr_os().map(|addr| addr.into_addr().unwrap())
    }

    #[allow(unsafe_code)] // FFI into the C++ implementation
    fn readable(&self) -> impl Future<Output = io::Result<()>> {
        let rpoll = unsafe { udt_sys::getrpoll() };
        rpoll.readable(self.inner).unwrap().map(|_| Ok(()))
    }

    #[allow(unsafe_code)] // FFI into the C++ implementation
    fn writable(&self) -> impl Future<Output = io::Result<()>> {
        let rpoll = unsafe { udt_sys::getrpoll() };
        rpoll.writable(self.inner).unwrap().map(|_| Ok(()))
    }

    #[allow(unsafe_code)] // FFI into the C++ implementation
    fn send_data(&self) -> u32 {
        let mut inflight = 0;
        let mut _optlen = 0;
        unsafe {
            udt_sys::getsockopt(
                self.inner,
                0,
                udt_sys::SocketOption::SendData,
                (&mut inflight as *mut i32).cast(),
                &mut _optlen,
            )
        };
        inflight.try_into().unwrap()
    }
}

impl Drop for Socket {
    #[allow(unsafe_code)] // FFI into the C++ implementation
    fn drop(&mut self) {
        unsafe { udt_sys::close(self.inner) };
    }
}

#[derive(Debug)]
pub struct Endpoint {
    binding: Socket,
}

#[derive(Debug)]
pub struct Listener {
    u: Socket,
}

#[derive(Debug)]
pub struct Connection {
    u: Socket,
}

impl Endpoint {
    #[allow(unsafe_code)] // FFI into the C++ implementation
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let inst = Instance::default();
        let binding = unsafe {
            udt_sys::socket(
                match addr {
                    SocketAddr::V4(_) => AF_INET,
                    SocketAddr::V6(_) => AF_INET6,
                },
                SOCK_DGRAM,
                0,
            )
        };
        if binding == INVALID_SOCK {
            return Err(unsafe { udt_getlasterror() });
        }
        let addr = OsSocketAddr::from(addr);
        let res = unsafe { udt_sys::bind(binding, addr.as_ptr().cast(), addr.len() as i32) };
        if res == -1 {
            unsafe { udt_sys::close(binding) };
            return Err(unsafe { udt_getlasterror() });
        }
        Ok(Self {
            binding: Socket {
                _inst: inst,
                inner: binding,
            },
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.binding.local_addr()
    }

    #[allow(unsafe_code)] // FFI into the C++ implementation
    fn listen_(&self, type_: i32, backlog: u32) -> io::Result<Socket> {
        let inst = Instance::default();
        let addr = self.binding.local_addr_os()?;
        let u = unsafe {
            udt_sys::socket(
                match addr.into_addr().unwrap() {
                    SocketAddr::V4(_) => AF_INET,
                    SocketAddr::V6(_) => AF_INET6,
                },
                type_,
                0,
            )
        };
        if u == INVALID_SOCK {
            return Err(unsafe { udt_getlasterror() });
        }
        let res = unsafe { udt_sys::bind(u, addr.as_ptr().cast(), addr.len() as i32) };
        if res == -1 {
            unsafe { udt_sys::close(u) };
            return Err(unsafe { udt_getlasterror() });
        }
        let res = unsafe { udt_sys::listen(u, backlog.try_into().unwrap_or(i32::MAX)) };
        if res == -1 {
            unsafe { udt_sys::close(u) };
            return Err(unsafe { udt_getlasterror() });
        }
        Ok(Socket {
            _inst: inst,
            inner: u,
        })
    }

    #[allow(unsafe_code)] // FFI into the C++ implementation
    fn connect_(&self, type_: i32, addr: SocketAddr, rendezvous: bool) -> io::Result<Socket> {
        let inst = Instance::default();
        let local_addr = self.binding.local_addr_os()?;
        let u = unsafe {
            udt_sys::socket(
                match local_addr.into_addr().unwrap() {
                    SocketAddr::V4(_) => AF_INET,
                    SocketAddr::V6(_) => AF_INET6,
                },
                type_,
                0,
            )
        };
        if u == INVALID_SOCK {
            return Err(unsafe { udt_getlasterror() });
        }
        let res = unsafe { udt_sys::bind(u, local_addr.as_ptr().cast(), local_addr.len() as i32) };
        if res == -1 {
            unsafe { udt_sys::close(u) };
            return Err(unsafe { udt_getlasterror() });
        }
        if rendezvous {
            let res = unsafe {
                udt_sys::setsockopt(
                    u,
                    0,
                    udt_sys::SocketOption::Rendezvous,
                    (&rendezvous as *const bool).cast(),
                    mem::size_of::<bool>() as i32,
                )
            };
            if res == -1 {
                unsafe { udt_sys::close(u) };
                return Err(unsafe { udt_getlasterror() });
            }
        }
        let addr = OsSocketAddr::from(addr);
        let res = unsafe { udt_sys::connect(u, addr.as_ptr().cast(), addr.len() as i32) };
        if res == -1 {
            unsafe { udt_sys::close(u) };
            return Err(unsafe { udt_getlasterror() });
        }
        Ok(Socket {
            _inst: inst,
            inner: u,
        })
    }

    pub fn listen(&self, backlog: u32) -> io::Result<Listener> {
        let u = self.listen_(SOCK_DGRAM, backlog)?;
        Ok(Listener { u })
    }

    pub async fn connect(
        self: &Arc<Self>,
        addr: SocketAddr,
        rendezvous: bool,
    ) -> io::Result<Connection> {
        let inner = self.clone();
        let con = spawn_blocking(move || {
            let u = inner.connect_(SOCK_DGRAM, addr, rendezvous)?;
            Ok::<_, io::Error>(Connection { u })
        })
        .await
        .unwrap()?;

        Ok(con)
    }
}

impl Listener {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.u.local_addr()
    }

    #[allow(unsafe_code)] // FFI into the C++ implementation
    pub fn try_accept(&self) -> io::Result<Connection> {
        let inst = Instance::default();
        let u = unsafe { udt_sys::accept(self.u.inner, ptr::null_mut(), ptr::null_mut()) };
        if u == INVALID_SOCK {
            return Err(unsafe { udt_getlasterror() });
        }
        Ok(Connection {
            u: Socket {
                _inst: inst,
                inner: u,
            },
        })
    }

    pub async fn accept(&self) -> io::Result<Connection> {
        loop {
            match self.try_accept() {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                v => break v,
            }
            let readable = self.u.readable();
            match self.try_accept() {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                v => break v,
            }
            readable.await?;
        }
    }
}

impl Connection {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.u.local_addr()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.u.peer_addr()
    }

    #[allow(unsafe_code)] // FFI into the C++ implementation
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let res = unsafe {
            udt_sys::recvmsg(
                self.u.inner,
                buf.as_mut_ptr().cast(),
                buf.len().try_into().unwrap_or(i32::MAX),
            )
        };
        if res == -1 {
            return Err(unsafe { udt_getlasterror() });
        }
        Ok(res.try_into().unwrap())
    }

    #[allow(unsafe_code)] // FFI into the C++ implementation
    pub fn try_send_with(
        &self,
        buf: &[u8],
        ttl: Option<Duration>,
        inorder: bool,
    ) -> io::Result<usize> {
        // TODO: inorder=false has a flawed implementation. UDT still applies windowing
        // in order to avoid replay attacks, so if a large burst of reliable out-of-order
        // datagrams are sent, the earliest ones will get stuck in retransmission hell
        // and UDT will livelock.

        // Therefore, inorder should always be set to true as a stopgap, excepting if there's a TTL.
        // We can instead mitigate replay attacks at a higher level (i.e. Noise).

        let inorder = inorder || ttl.is_none();

        let res = unsafe {
            udt_sys::sendmsg(
                self.u.inner,
                buf.as_ptr().cast(),
                buf.len().try_into().unwrap_or(i32::MAX),
                ttl.map_or(-1, |ttl| ttl.as_millis().try_into().unwrap()),
                inorder,
            )
        };
        if res == -1 {
            return Err(unsafe { udt_getlasterror() });
        }
        Ok(res.try_into().unwrap())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.try_recv(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                v => break v,
            }
            let readable = self.u.readable();
            match self.try_recv(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                v => break v,
            }
            readable.await?;
        }
    }

    pub async fn send_with(
        &self,
        buf: &[u8],
        ttl: Option<Duration>,
        inorder: bool,
    ) -> io::Result<usize> {
        loop {
            match self.try_send_with(buf, ttl, inorder) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                v => break v,
            }
            let writable = self.u.writable();
            match self.try_send_with(buf, ttl, inorder) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                v => break v,
            }
            writable.await?;
        }
    }

    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.send_with(buf, None, true).await
    }

    pub async fn flush(&self) -> io::Result<()> {
        loop {
            if self.u.send_data() == 0 {
                break;
            }
            let writable = self.u.writable();
            if self.u.send_data() == 0 {
                break;
            }
            writable.await?;
        }
        Ok(())
    }
}
