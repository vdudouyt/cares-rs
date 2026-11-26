cares-tests
=============
A standalone c-ares testing suite derived from original implementation (c-ares 1.34.6).

## Synopsis
```
$ ./arestest /path/to/c-ares/libcares.so   # Test original c-ares (1.34.6)
$ ./arestest ../../target/release/libcares.so  # Test cares-rs
```

Both libraries are now named `libcares.so`, so always pass an explicit path. A bare
`./arestest libcares.so` makes `dlopen` search the system library path and can silently
test the distro's c-ares instead of the build under test.

## Integration tests (arestest)

Tests ported from the original c-ares test suite. The test binary loads the
library at runtime via dlsym, so the same binary can test both the original c-ares
and cares-rs — only the path argument changes.

Tests are organized by file:
- `ares-test-mock.cc` / `ares-test-mock-ai.cc` — mock DNS server tests (search domains, failover, callbacks, cache, etc.)
- `ares-test-live.cc` — live DNS resolution tests (localhost, gethostbyname, getnameinfo)
- `ares-test-parse-*.cc` — DNS response parsing for each record type (A, AAAA, MX, SRV, TXT, etc.)
- `ares-test-misc.cc` — utility functions (GetServers, ExpandName, CreateQuery, etc.)
- `ares-test-init.cc` — library/channel initialization and option handling

### Supported test categories
- **EDNS / DNS cookies / DNS 0x20** — implemented and covered by the restored upstream tests.
- **Event thread** — `ARES_OPT_EVENT_THREAD` is implemented; `ares_threadsafety()` returns 1.
  The event-thread suites run once per backend (`EPOLL`, `POLL`, `SELECT`), as upstream does on Linux.
  The manual reactor API (`ares_fds`/`ares_process`/`ares_process_fd`/`ares_timeout`) is
  still supported for channels without the event thread.

### Remaining excluded test categories
- **Alloc-failure injection** — not applicable to Rust
- **Container/namespace** — tests access channel struct internals incompatible with our opaque Rust struct
- **Internal API** — tests c-ares private functions not exposed via FFI

## Fuzz corpus tests (aresfuzz, aresfuzzname)

Two standalone binaries that feed corpus files through parser functions to catch
crashes. No network I/O — pure in-memory parsing.

```
$ ./aresfuzz ../../target/release/libcares.so fuzzinput/*       # 74 binary DNS packets
$ ./aresfuzzname ../../target/release/libcares.so fuzznames/*   # 45 text corpus files (domain names, URIs)
```

**aresfuzz** runs in modern mode: `ares_dns_parse()` -> accessor functions -> `ares_dns_write()`
round-trip on each corpus file. Corpus includes real crash cases from ClusterFuzz/OSS-Fuzz.

**aresfuzzname** runs in legacy mode: `ares_create_query()` with each corpus file as a domain name.

## Infrastructure

- `loader.cc` / `loader.h` — dlsym-based dynamic loader with IMPL_SHIM macro
- `dns-proto.cc` / `dns-proto.h` — DNS packet builder for mock server tests
- `ares-test.cc` / `ares-test.h` — test fixtures, mock server, result types, utilities
- `ares-fuzz-main.cc` — fuzz corpus driver (takes library path + corpus files)
- `src/include/ares_buf.h` — minimal string builder for modern fuzz mode
- `src/include/ares_mem.h` — stub header with declarations for c-ares 1.34.6 APIs

## Notes
- Tests are copied from the original c-ares implementation with minimal changes
- Updates are performed by syncing ares-test-*.cc files from original implementation
- The test harness (loader, driver, stubs) is custom for cares-rs
