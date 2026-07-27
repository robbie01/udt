# Vendored upstream UDT

Unmodified sources from <https://github.com/dorkbox/udt>, commit
`8272c251deb8bfd7289646b7604f1079b59194d0` ("Updated readme (remove java bits)",
2017-12-03), taken from that repository's `src/` directory.

**Do not edit these files.** They exist to be a known-good reference for
regression-testing `udt-compat/udt-sys/udt/`, which is a heavily modified fork
of this same code. Editing them defeats the purpose. If upstream needs to be
re-vendored, replace the whole directory and update this file.

Licensing is upstream's own; `LICENSE`, `LICENSE.BSD` and `LICENSE.Apachev2`
are copied here alongside the sources.

## Known differences from the fork

Recorded because they are the things most likely to matter for interoperability:

- **Payload size.** Upstream computes `m_iPktSize = m_iMSS - 28` (IPv4 header +
  UDP header), giving a 1456-byte payload at the default 1500 MSS. The fork
  hardcodes `IP_AND_UDP_OVERHEAD = 48` (IPv6-sized), giving 1436. `udt-proto`
  followed the fork. The two still interoperate, because reassembly is driven by
  the per-packet boundary flags rather than by size — `message_boundaries_*` in
  `tests/upstream-compat` covers this deliberately.
- **Files.** The fork deletes `epoll.cpp` (replaced by a Rust readiness poller)
  and `md5.cpp` (replaced by `rutil::compute_md5` over the cxx bridge).
- **Blocking mode.** The fork removes it entirely: `UDT_SNDSYN` is commented out,
  `UDT_CONNSYN = 2` squats on upstream's `UDT_RCVSYN` slot, and `sendmsg`/
  `recvmsg` return `-6001`/`-6002` immediately rather than waiting. Socket-option
  numbering in `udt-orig/src/ffi.rs` therefore comes from upstream's `udt.h`,
  never the fork's.
