//! Single-connection TCP loopback throughput, as fast as this machine goes.
//!
//! Exists to bound the UDT numbers: a reliable stream over loopback cannot beat
//! what the kernel's own reliable stream does on the same box, so this is the
//! ceiling to read them against.
//!
//! Several shapes, because the answer depends on more than the protocol:
//!
//! * `blocking` — two OS threads, plain `std::net`. No runtime, no readiness
//!   machinery; usually the fastest thing available and the honest ceiling.
//! * `tokio1`   — one multi-threaded tokio runtime, both halves as tasks.
//! * `tokio2`   — two current-thread runtimes on two OS threads, so the halves
//!   cannot be scheduled onto the same core.
//! * `compio`   — io_uring (on Linux), one runtime per thread.
//!
//! Usage: `tcp-bench [mode] [buf_kib] [total_mib] [--pin]`
//! With no mode, runs the full matrix.

#![deny(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Instant;

const DEFAULT_TOTAL_MIB: usize = 4096;
const DEFAULT_BUF_KIB: usize = 256;

fn report(label: &str, buf_kib: usize, bytes: usize, secs: f64) {
    println!(
        "[{label:<16} buf={buf_kib:>5} KiB] {:>8.1} MB/s   {:>5} MiB in {:.2}s",
        bytes as f64 / 1e6 / secs,
        bytes / (1024 * 1024),
        secs,
    );
}

/// Pin the calling thread to a specific core, if asked and possible.
fn pin(core_index: usize, enabled: bool) {
    if !enabled {
        return;
    }
    if let Some(ids) = core_affinity::get_core_ids()
        && let Some(id) = ids.get(core_index).copied()
    {
        core_affinity::set_for_current(id);
    }
}

/// Force a maximum segment size, so TCP packetises at the same rate a real
/// 1500-byte path would.
///
/// Loopback has a 65536-byte MTU, so an unconstrained TCP stream moves data in
/// enormous segments and does a small fraction of the per-packet work a
/// datagram protocol pinned to a 1500-byte MSS must do. Comparing against that
/// measures the loopback MTU, not the protocol.
#[allow(unsafe_code)] // setsockopt: no safe wrapper exposes TCP_MAXSEG
fn set_mss<F: AsRawFd>(sock: &F, mss: u32) {
    let v = mss as libc::c_int;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            (&raw const v).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        eprintln!("warning: could not set TCP_MAXSEG={mss}: {}", std::io::Error::last_os_error());
    }
}

fn connect_with_mss(addr: SocketAddr, mss: Option<u32>) -> TcpStream {
    let Some(mss) = mss else {
        return TcpStream::connect(addr).unwrap();
    };
    // The option must be set before connect, so the socket is built by hand.
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    set_mss(&s, mss);
    s.connect(&addr.into()).unwrap();
    s.into()
}

// ── Blocking: two OS threads, no runtime ─────────────────────────────────────

fn bench_blocking(total: usize, buf: usize, pinned: bool, mss: Option<u32>) -> (usize, f64) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    if let Some(m) = mss {
        // Accepted sockets inherit the listener's segment size.
        set_mss(&listener, m);
    }
    let addr = listener.local_addr().unwrap();

    let reader = std::thread::spawn(move || {
        pin(0, pinned);
        let (mut s, _) = listener.accept().unwrap();
        s.set_nodelay(true).unwrap();
        let mut b = vec![0u8; buf];
        let mut got = 0usize;
        while got < total {
            match s.read(&mut b) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => panic!("read: {e}"),
            }
        }
        got
    });

    // Connect before starting the clock so setup is not measured.
    let mut s = connect_with_mss(addr, mss);
    s.set_nodelay(true).unwrap();
    let writer = std::thread::spawn(move || {
        pin(2, pinned);
        let b = vec![0x5Au8; buf];
        let mut sent = 0usize;
        let start = Instant::now();
        while sent < total {
            s.write_all(&b).unwrap();
            sent += buf;
        }
        s.flush().unwrap();
        start.elapsed()
    });

    let elapsed = writer.join().unwrap();
    let got = reader.join().unwrap();
    (got, elapsed.as_secs_f64())
}

// ── tokio, one multi-threaded runtime ────────────────────────────────────────

fn bench_tokio_one_runtime(total: usize, buf: usize) -> (usize, f64) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let reader = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.set_nodelay(true).unwrap();
            let mut b = vec![0u8; buf];
            let mut got = 0usize;
            while got < total {
                match s.read(&mut b).await {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(e) => panic!("read: {e}"),
                }
            }
            got
        });

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.set_nodelay(true).unwrap();
        let start = Instant::now();
        let writer = tokio::spawn(async move {
            let b = vec![0x5Au8; buf];
            let mut sent = 0usize;
            while sent < total {
                s.write_all(&b).await.unwrap();
                sent += buf;
            }
            s.flush().await.unwrap();
        });
        writer.await.unwrap();
        let secs = start.elapsed().as_secs_f64();
        (reader.await.unwrap(), secs)
    })
}

// ── tokio, one current-thread runtime per side ───────────────────────────────

fn bench_tokio_two_runtimes(total: usize, buf: usize, pinned: bool) -> (usize, f64) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();

    let reader = std::thread::spawn(move || {
        pin(0, pinned);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            use tokio::io::AsyncReadExt;
            let l = tokio::net::TcpListener::from_std(listener).unwrap();
            let (mut s, _) = l.accept().await.unwrap();
            s.set_nodelay(true).unwrap();
            let mut b = vec![0u8; buf];
            let mut got = 0usize;
            while got < total {
                match s.read(&mut b).await {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(e) => panic!("read: {e}"),
                }
            }
            got
        })
    });

    let writer = std::thread::spawn(move || {
        pin(2, pinned);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            use tokio::io::AsyncWriteExt;
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.set_nodelay(true).unwrap();
            let b = vec![0x5Au8; buf];
            let mut sent = 0usize;
            let start = Instant::now();
            while sent < total {
                s.write_all(&b).await.unwrap();
                sent += buf;
            }
            s.flush().await.unwrap();
            start.elapsed()
        })
    });

    let elapsed = writer.join().unwrap();
    let got = reader.join().unwrap();
    (got, elapsed.as_secs_f64())
}

// ── compio (io_uring on Linux), one runtime per thread ───────────────────────

fn bench_compio(total: usize, buf: usize, pinned: bool) -> (usize, f64) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let reader = std::thread::spawn(move || {
        pin(0, pinned);
        compio::runtime::Runtime::new().unwrap().block_on(async move {
            use compio::io::AsyncRead;
            let l = compio::net::TcpListener::from_std(listener).unwrap();
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = vec![0u8; buf];
            let mut got = 0usize;
            while got < total {
                // compio takes ownership of the buffer and hands it back, so
                // there is no borrow to keep alive across the completion.
                let (res, ret) = s.read(b).await.into();
                b = ret;
                match res {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(e) => panic!("read: {e}"),
                }
            }
            got
        })
    });

    let writer = std::thread::spawn(move || {
        pin(2, pinned);
        compio::runtime::Runtime::new().unwrap().block_on(async move {
            use compio::io::{AsyncWrite, AsyncWriteExt};
            let mut s = compio::net::TcpStream::connect(addr).await.unwrap();
            let mut b = vec![0x5Au8; buf];
            let mut sent = 0usize;
            let start = Instant::now();
            while sent < total {
                let (res, ret) = s.write_all(b).await.into();
                b = ret;
                res.unwrap();
                sent += buf;
            }
            s.flush().await.unwrap();
            start.elapsed()
        })
    });

    let elapsed = writer.join().unwrap();
    let got = reader.join().unwrap();
    (got, elapsed.as_secs_f64())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pinned = args.iter().any(|a| a == "--pin");
    let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();

    let mode = pos.first().map(|s| s.as_str()).unwrap_or("all");
    let buf_kib: usize = pos.get(1).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_BUF_KIB);
    let total_mib: usize = pos.get(2).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_TOTAL_MIB);
    let total = total_mib * 1024 * 1024;

    let run = |m: &str, buf_kib: usize| {
        let buf = buf_kib * 1024;
        let (bytes, secs) = match m {
            "blocking" => bench_blocking(total, buf, pinned, None),
            "blocking-mss" => bench_blocking(total, buf, pinned, Some(1460)),
            "tokio1" => bench_tokio_one_runtime(total, buf),
            "tokio2" => bench_tokio_two_runtimes(total, buf, pinned),
            "compio" => bench_compio(total, buf, pinned),
            other => panic!("unknown mode {other}"),
        };
        let label = if pinned { format!("{m}+pin") } else { m.to_string() };
        report(&label, buf_kib, bytes, secs);
    };

    if mode == "mss" {
        // Same packetisation rate as a 1500-byte path, for comparison against a
        // datagram protocol that cannot use jumbo segments.
        for kib in [64, 256, 1024] {
            run("blocking", kib);
            run("blocking-mss", kib);
        }
        return;
    }
    if mode == "all" {
        for m in ["blocking", "tokio1", "tokio2", "compio"] {
            for kib in [64, 256, 1024] {
                run(m, kib);
            }
        }
    } else if mode == "sweep" {
        for kib in [16, 64, 256, 1024, 4096] {
            run("blocking", kib);
        }
    } else {
        run(mode, buf_kib);
    }
}
