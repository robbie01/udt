# UDT test harness

This branch exists so that `master` contains **only** the Rust UDT
implementation. Everything here is a reference or comparison point, not part of
the library:

| Directory | What it is |
|---|---|
| `udt-compat/` | Bindings to the heavily-modified C++ UDT fork, plus its vendored sources (`udt-sys/udt/`). |
| `udt-orig/` | Unmodified upstream <https://github.com/dorkbox/udt> at `8272c25`, for regression-testing the fork. |
| `cpp-interop/` | Rust ↔ C++ interop tests and the C++-baseline benchmarks. |
| `upstream-compat/` | Rust ↔ *unmodified upstream* smoke tests, blocking mode only. |
| `quinn-bench/` | Quinn loopback throughput, as an independent reference point. |
| `tcp-bench/` | Kernel TCP loopback throughput — the ceiling to read UDT against. |

## Using it

Check this branch out beside the main clone — the path dependencies resolve to
`../udt`:

```
git worktree add ../udt-harness harness
cd ../udt-harness
cargo test                                   # correctness
cargo test --release -- --ignored --nocapture --test-threads=1   # benchmarks
```

Both checkouts share one `.git`, so the harness tracks whatever is committed on
`master` without any copying.

## Why `udt-compat` and `udt-orig` must not share a binary

Both compile a complete copy of UDT, and their mangled C++ symbols are
byte-identical (`CUDT`, `CUDTUnited`, …); the generated cxx shims collide too,
since the shim name embeds only the cxx version. Linking both is an ODR
violation with two `CUDT::s_UDTUnited` singletons and two independent
`startup()`/`cleanup()` refcounts.

`cpp-interop` depends on `udt-compat`; `upstream-compat` depends on `udt-orig`.
Never add the other to either.
