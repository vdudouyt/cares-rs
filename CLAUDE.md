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

The crate is split into three sections by hard boundaries, enforced by the compiler:

- **`src/async_runtime/`** — `#![forbid(unsafe_code)]`. The protocol-agnostic async IO runtime: the `Socket`/`SocketFactory` traits (`socket.rs`), the pure-IO reactor with its generic `QueryIo<A>` mailbox + readiness arms (`poll_recv`/`poll_writable`/`poll_timeout`, raced with `futures::select_biased!`) (`executor.rs`), and tokio-style async connections with caller-supplied stream framing (`FrameOf`) and tag demux (`TagOf`) (`conn.rs`). Imports **std + `futures-util`** (the `select_biased!` macro + `FutureExt` only) — nothing here names DNS, a wire format, or `crate::core` (grep-enforced wall); the DNS side supplies `dns_frame`/`dns_tag`. The reactor is waker-less (driven by `ares_process`), so futures compose only via `select_biased!`/`.await`; waker-gated combinators (`FuturesUnordered`, `for_each_concurrent`) poll once and wedge — never use them.
- **`src/core/`** — `#![forbid(unsafe_code)]`. All resolver logic — DNS wire codec, system config, and the query lifecycles (self-contained async fns on `AsyncClient` driving `async_runtime` sockets) — as pure safe Rust behind pointer-free signatures. This is where behavior lives and where you make decisions.
- **`src/ffi/`** — every `unsafe` line in the crate. Marshals C arguments, implements the `Socket` traits over the C socket-function table, drives the reactor from `ares_process`, and *executes* the decisions core returns. Shims, builders, trampolines only — no policy. `src/lib.rs` sets `#![deny(unsafe_op_in_unsafe_fn)]` and re-exports `ffi::*` as the public API.

The refactoring goal is a shrinking unsafe surface: any logic found in `ffi/` should move into a `forbid(unsafe_code)` core function. The ratchet gate protects this.

### core module map

- `async_client.rs` — **THE resolver.** One struct, `AsyncClient`, is both the channel state (config/options/server list/shared pools — ffi's `ChannelData` wraps one instance; every config/lifecycle export is a method: `apply_options`/`saved_options`/`set_servers`/`duplicate`/…) and the resolver client: each entry shim mints a per-lookup copy via `derive()` (fresh `QueryIo` mailbox, shared `Rc`s for cache/health/tcp-pool, endpoints snapshotted from current config) and spawns one of the async lifecycle methods (`query_raw`/`gethostbyname`/`gethostbyaddr`/`getnameinfo`/`search`/`getaddrinfo`) — thin preflight + result-shaping shells. The two address lifecycles (`gethostbyname`/`getaddrinfo`) share the `resolve_addrinfo` DNS-phase core (search-name iteration + per-name `query_families` A/AAAA race with A-cancels-AAAA + first-name `run_probe`), mirroring upstream where `ares_gethostbyname` is a shell over `ares_getaddrinfo`; `gethostbyname` adds single-family Hostent pick + cache-store + sortlist. All ultimately drive the single-query `request()` (with the `connect_failover` helper and the `run_probe` failover peer) over `async_runtime` conns. Also here, in marked sections: the entry preflights (`search_precheck`, `service_to_port`, nameinfo assembly, `hosts_file_lookup`), the DNS wire builders (`dns_query_payload`/`build_query`/`frame_tcp` + the `dns_frame`/`dns_tag` codecs handed to the runtime), and the `ares_fds`/`ares_timeout` tallies (`nfds`/`clamp_timeout`).
- `lookup.rs` — the per-reply verdict logic: `on_datagram`/`on_timeout` (retry / failover / TC-retry decisions as pure functions), `summarize`/`qid_matches`, `SearchPlan` (ndots/bare-name iteration), `ServerHealth` (lowest-failures-first selection), `is_localhost`/`is_onion_domain`.
- `hostent.rs` — `HostentBlueprint` (family/alias/addr decisions) + `addrttl_fill`.
- `dns_record.rs` — the record model (`ares_dns_record_t`/`ares_dns_rr_t`) + codec + metadata tables.
- `packets.rs` — DNS wire parsing (+ `AddrRecord`, `buf_to_ip`). `sortlist.rs`, `sysconfig.rs` (resolv.conf, `SysConfig`), `servers_csv.rs`, `hostfile.rs`, `services.rs`, `response.rs`, `cache.rs` — the rest of the pure surface.

### ffi module map

`mod.rs` holds typedefs/consts and re-exports. `lookups.rs` = entry shims (each marshals its C args, calls `state.derive()` + one lifecycle method, and `spawn`s the future with a one-line delivery closure) + the per-signature `on_*_reply` delivery handlers (`on_raw`/`on_dnsrec`/`on_hostent`/`on_nameinfo`/`on_addrinfo` — the only sites that call a C callback; each takes `Result<output, c_int>` = `Ok` on completion / `Err(status)` on cancel). `channel.rs` = `ChannelData` (= `AsyncClient` + the C callback fn-pointer fields) + the erased in-flight query slot (`trait PendingQuery` + `struct Query<T>{fut,out,on}`; `spawn` polls → `deliver(None)` on completion / `deliver(Some(status))` on `ares_cancel`/`ares_destroy`) + the reactor driver (`process_channel`) + `invoke_server_state_callback` + linked-list/fd_set marshal. `process.rs` = the `ares_process`/`ares_process_fd` entry shims. `parsers.rs`, `addrinfo.rs`, `dns_record.rs` (57 shims), `convert.rs` (cstr/sockaddr), `ares_hostent.rs`/`ares_data.rs`/`ares_options.rs`/`ares_socket.rs` = marshalling + C-callback trampolines.

### Behavior notes

- **Socket-creation failure** (EMFILE/fd exhaustion) → `ARES_ECONNREFUSED`, never a panic. The socket factory returns `io::Result`; the connect-with-failover loops treat a creation failure like a dead server (fail over, or return `ECONNREFUSED` when the attempt budget is spent — matches upstream `ares_conn.c`). In `getaddrinfo`/`gethostbyname` each family (A/AAAA) is an independent `request` future (via `query_families`), so one family's `ECONNREFUSED` just means that family contributes no records; the other still delivers.
- **`ares_options` is the 1.34.6 layout** (152 bytes, includes `server_failover_opts` as a real field, accessed by direct field access — no offset arithmetic). Caller-allocated with the 1.34.6 header.
- **No EDNS**, **no event thread** (`ares_threadsafety()` = 0, `ARES_OPT_EVENT_THREAD` → `ENOTIMP`; the manual reactor API `ares_fds`/`ares_process`/`ares_process_fd` is retained), **no malloc-failure tests** — all deliberate exclusions.
- RCODE map: 0=OK, 1=FORMERR, 2=SERVFAIL, 3=NOTFOUND, 4=NOTIMP, 5=REFUSED, 6+=ENODATA. RFC 6761 `localhost`/`*.localhost` → loopback. `.onion` rejected. Empty nameserver list → `ARES_ENOSERVER`.
- The C header is generated by `build.rs` via cbindgen into `include/cares.h` (git-ignored). `example.c` in `examples/` is the drop-in smoke test compiled in CI.
