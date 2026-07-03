# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

A Rust rewrite of the [c-ares](https://c-ares.org/) asynchronous DNS resolver, shipped as a drop-in `libcares_rs.so` with the c-ares **1.34.6** C ABI. `ares_version()` returns `"1.34.6"`; the authoritative header is `tests/cares-tests/src/include/cares/ares.h` (the dev box's `/usr/include/ares.h` is 1.27-era — do not use it).

## Rules

* Use non-blocking I/O following the reactor pattern. Never use blocking I/O requests.
* All functions and structures exported in C must be `pub`.
* Commit with **zero** build/clippy warnings.
* **Porting tests:** copy `.c`/`.cc` files from the original c-ares tree at `/root/c-ares-1.34.6/` with as few changes as possible, for logical consistency and easy updates. Copy them verbatim; the only tests you may comment out or skip are EDNS and malloc/alloc-failure ones.

## Build, lint, test

```bash
cargo build --release            # produces target/release/libcares_rs.so (+ include/cares.h via cbindgen)
cargo clippy --all-targets        # must be warning-clean before committing
cargo test                        # Rust-side integration tests (tests/*.rs)
cargo test --test miri_memory     # the FFI alloc/free + parsing matrix
```

The canonical behavior suite is the **original c-ares C++ gtest binary**, run against the `.so` via `dlsym`:

```bash
cd tests/cares-tests && cmake . && make
./arestest ../../target/release/libcares_rs.so \
  "--gtest_filter=-*EDNS*:*DownServer*:*MaxQueries*:*StayOpen*"   # the CI filter
```

- Run one test: append `--gtest_filter=Foo.Bar` (single filter; the CI filter above is the exclusion set).
- `Live*` tests need real network (the box has it); everything else is mocked.
- Excluded categories (`EDNS`, `DownServer`, `MaxQueries`, `StayOpen`, plus alloc-failure/container/event-thread/internal) are unsupported by design — don't try to make them pass.
- Fuzz corpora: `./aresfuzz <so> fuzzinput/*` (DNS parsing) and `./aresfuzzname <so> fuzznames/*` (server CSV).

CI additionally runs the gtest suite under **Valgrind** (`--leak-check=full`), and **Miri** on `cargo miri test` (`-Zmiri-tree-borrows -Zmiri-disable-isolation`) to catch UB/leaks in the unsafe FFI surface. Miri can't touch real sockets, so reactor tests are `#[cfg_attr(miri, ignore)]`.

### CI gates that fail the build (`.github/workflows/`)

- **ABI header** — `include/cares.h` (cbindgen-generated on every build from `src/`) must match `ci-data/cares.h.baseline`.
- **Exports** — the `.so`'s `ares_*` symbol set must match `ci-data/exports.baseline`.
- **Unsafe ratchet** — `python3 tools/unsafe_lines.py --check tools/unsafe_baseline.json`. The count of lines inside `unsafe` contexts may never grow past the baseline. If you legitimately move logic and the count drops, run `--update` to lower the ratchet; it must never rise.

When you change the FFI surface, regenerate and re-baseline: `cargo build`, then update `ci-data/cares.h.baseline` / `ci-data/exports.baseline` as part of the same change.

## Architecture

The crate is split into two halves by a hard safety boundary, enforced by the compiler:

- **`src/core/`** — `#![forbid(unsafe_code)]`. All resolver logic — DNS wire codec, transport/reactor engine, system config, and the entire query-lifecycle state machine — as pure safe Rust behind pointer-free signatures. This is where behavior lives and where you make decisions.
- **`src/ffi/`** — every `unsafe` line in the crate. Marshals C arguments, performs raw I/O, and *executes* the decisions core returns. Shims, builders, trampolines only — no policy. `src/lib.rs` sets `#![deny(unsafe_op_in_unsafe_fn)]` and re-exports `ffi::*` as the public API.

The refactoring goal is a shrinking unsafe surface: any logic found in `ffi/` should move into a `forbid(unsafe_code)` core function. The ratchet gate protects this.

### core module map

- `api.rs` — **one handler per `ares_*` export.** Each FFI shim marshals its C args and makes exactly one call in here; preflights, launch loops, and cache policy are private details of these handlers, not seams the ffi layer reassembles. `make_userdata` factories mint the ffi userdata around core-owned state-machine handles (closures capture only `Copy`/`Rc` — never a live `RefCell` borrow).
- `lookup.rs` — **the query state machine.** Every retry / failover / search-iteration / TC-retry / AF_UNSPEC decision lives here as pure logic. `SearchSm` (ares_search), `HostByNameSm` (gethostbyname), `AddrInfoSm` (getaddrinfo's parallel A+AAAA batch with a `pending` join counter); plus `SearchPlan` (ndots/bare-name iteration) and `ServerHealth` (lowest-failures-first selection). Machines consume events (parsed reply / I/O error) and return actions; `api.rs` drives them. Its module doc is the reading map.
- `ares.rs` — the transport engine `Ares<T>`/`Task<T>` (UDP + TCP) over `dyn Transport`.
- `transport.rs` — `Transport`/`TransportFactory` traits (`ffi::ares_socket` implements them).
- `channel.rs` — `ChannelState<T>`, all pure channel state (ffi's `ChannelData` = this + the C callback fn-pointer fields).
- `preflight.rs` — entry cascades, `service_to_port`, `assemble_nameinfo`, `AddrInfo`.
- `launch.rs` — issue/reissue/launch_pooled/drive_addrinfo/probe + reactor helpers; the `Consent` closure type.
- `hostent.rs` — `HostentBlueprint` (family/alias/addr decisions) + `addrttl_fill`.
- `dns_record.rs` — the record model (`ares_dns_record_t`/`ares_dns_rr_t`) + codec + metadata tables.
- `packets.rs` — DNS wire parsing (+ `AddrRecord`, `buf_to_ip`). `sortlist.rs`, `sysconfig.rs` (resolv.conf, `SysConfig`), `servers_csv.rs`, `hostfile.rs`, `services.rs`, `query_builder.rs`, `response.rs` — the rest of the pure surface.

### ffi module map

`mod.rs` holds typedefs/consts and re-exports. `lookups.rs` = entry shims + the `Callback` enum (dispatches replies to per-type core handlers; `Probe` variant = server-failover probe with no user callback) + userdata factories. `channel.rs` = `ChannelData` wrapper + linked-list/fd_set marshal. `process.rs` = the reactor driver + `sock_consent`. `parsers.rs`, `addrinfo.rs`, `dns_record.rs` (57 shims), `convert.rs` (cstr/sockaddr), `ares_hostent.rs`/`ares_data.rs`/`ares_options.rs`/`ares_socket.rs` = marshalling + C-callback trampolines.

### Behavior notes

- **Socket-creation failure** (EMFILE/fd exhaustion) → `ARES_ECONNREFUSED`, never a panic. The socket-creating core methods return `Result<(), io::Error>`; FFI call sites check `is_err()` and fail over or deliver ECONNREFUSED (matches upstream `ares_conn.c`). `getaddrinfo` pre-increments `pending` across the whole A+AAAA batch so a per-query failure can't free state early.
- **`ares_options` is the 1.34.6 layout** (152 bytes, includes `server_failover_opts` as a real field, accessed by direct field access — no offset arithmetic). Caller-allocated with the 1.34.6 header.
- **No EDNS**, **no event thread** (`ares_threadsafety()` = 0, `ARES_OPT_EVENT_THREAD` → `ENOTIMP`; the manual reactor API `ares_fds`/`ares_process`/`ares_process_fd` is retained), **no malloc-failure tests** — all deliberate exclusions.
- RCODE map: 0=OK, 1=FORMERR, 2=SERVFAIL, 3=NOTFOUND, 4=NOTIMP, 5=REFUSED, 6+=ENODATA. RFC 6761 `localhost`/`*.localhost` → loopback. `.onion` rejected. Empty nameserver list → `ARES_ENOSERVER`.
- The C header is generated by `build.rs` via cbindgen into `include/cares.h` (git-ignored). `example.c` in `examples/` is the drop-in smoke test compiled in CI.
