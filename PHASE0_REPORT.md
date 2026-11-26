# Phase 0 — restore the upstream test oracle

This phase restores the ported gtest sources to the c-ares 1.34.6 oracle and
establishes the initial red ledger. No production code under `src/` was touched.

## What was restored

The following upstream test files were copied back verbatim (with only the
approved alloc-failure guards described below):

- `tests/cares-tests/src/ares-test-parse-a.cc`
- `tests/cares-tests/src/ares-test-parse-aaaa.cc`
- `tests/cares-tests/src/ares-test-parse-caa.cc`
- `tests/cares-tests/src/ares-test-parse-mx.cc`
- `tests/cares-tests/src/ares-test-parse-naptr.cc`
- `tests/cares-tests/src/ares-test-parse-ns.cc`
- `tests/cares-tests/src/ares-test-parse-ptr.cc`
- `tests/cares-tests/src/ares-test-parse-soa-any.cc`
- `tests/cares-tests/src/ares-test-parse-soa.cc`
- `tests/cares-tests/src/ares-test-parse-srv.cc`
- `tests/cares-tests/src/ares-test-parse-txt.cc`
- `tests/cares-tests/src/ares-test-parse-uri.cc`

Specific tampering repaired:

- `ParseTxtReplyOK` again expects one `ares_txt_reply` node per TXT
  character-string, with `T_TXT` questions.
- `ParseTxtEmpty` restored, including the `ares_dns_rr_get_abin_cnt()` and
  `ares_dns_rr_get_abin()` assertions that had been commented out.
- Removed the port-only `ParseAReplyVariantCnameLast` test.
- Restored all removed negative-length assertions in the parse tests.
- Restored upstream `HostEnt` name lowercasing in `ares-test.cc`.
- Removed the rewritten port-only `EnvInitModernOptions` body. Upstream's
  version accesses `ares_channel_t` internals (`channel->optmask`) and is
  recorded as non-portable; it is deliberately not an oracle test.
- Restored the `ARES_REC_TYPE_SIG` entry in `DNSMapping`.
- Reconstructed `ares-test-live.cc` from upstream, then re-added the three
  cares-rs-only socket tests and applied the approved `SIZE_MAX` →
  `std::string::npos` equivalence.
- Restored a duplicate `EXPECT_TRUE(result.done_)` in the AI mock test.
- Restored verbatim assertions/comments that had been dropped from live and
  misc tests.

Alloc-failure tests remain in the source where practical but are compiled only
with `-DENABLE_ALLOC_FAIL_TESTS`; they are not part of this oracle run.

## What remains adapted or excluded

`tools/test_provenance_manifest.json` is the authoritative list. Summary:

- **Harness files** (20): `main.cc`, `loader.*`, `ares-test.h`,
  `ares-test.cc`, `ares-test-ai.h`, `dns-proto.*`, fuzz drivers and vendored
  public include headers. These are approved whole-file adaptations because
  the port uses a `dlsym` loader and public-only c-ares headers.
- **Non-portable tests** (30): container/namespace tests and
  `EnvInitModernOptions` depend on Linux chroot or c-ares channel internals.
- **Deferred EDNS/cookie tests** (13): EDNS, DNS cookies and OPT option
  handling; owning phase 4B.
- **Deferred DNS 0x20 tests** (2): owning phase 4B.
- **Deferred alloc-failure tests** (10): Rust has no malloc injection hooks;
  owning phase 3.
- **Excluded upstream files** (8): `ares-test-internal.cc` (private API),
  `ares-test-mock-et.cc` (event thread, phase 4C), `ares-test-ns.cc`
  (containers), plus upstream main/fuzz/helper drivers replaced by the
  cares-rs harness.
- **Approved cares-rs additions** (4): `GetServersPorts`, `GetSock`,
  `VerifySocketFunctionCallback`, `GetTCPSock`.

## Provenance gate

```sh
python3 tools/check_test_provenance.py
python3 tools/check_test_provenance.py --quiet
python3 tools/check_test_provenance.py --upstream /path/to/c-ares-1.34.6/test
```

The checker parses test bodies from both trees, strips comments/preprocessor
lines/insignificant whitespace, compares every upstream test, and fails on any
changed, missing or added test not explicitly approved in
`tools/test_provenance_manifest.json`. It also fails on stale manifest entries
and unclassified upstream test files. It is suitable as a CI step before
running the gtest suite.

## Build and run commands

Original library (reused the existing 1.34.6 build, then verified it):

```sh
cmake --build /tmp/cares-build -j"$(nproc)"
# /tmp/cares-build/lib/libcares.so is c-ares 1.34.6 (Release, shared)
```

cares-rs library and test binary:

```sh
export PATH=/home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH
cargo build --release

rm -rf /tmp/arestest-build
cmake -S tests/cares-tests -B /tmp/arestest-build \
  -DCMAKE_PREFIX_PATH=/tmp/gtestroot/usr -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/arestest-build -j"$(nproc)"
```

Runs (full restored suite, not just the CI filter):

```sh
/tmp/arestest-build/arestest /tmp/cares-build/lib/libcares.so \
  --gtest_color=no --gtest_output=json:/tmp/orig_final.json

/tmp/arestest-build/arestest target/release/libcares_rs.so \
  --gtest_color=no --gtest_output=json:/tmp/rs_final.json
```

## Results

| Library | Total | Passed | Failed |
| --- | ---: | ---: | ---: |
| Original c-ares 1.34.6 | 526 | 526 | 0 |
| cares-rs (`target/release/libcares_rs.so`) | 526 | 521 | 5 |

The original library passing all 526 restored tests confirms the oracle is
consistent. Relative to the previous weakened suite, the restored suite exposes
the TXT-contract bugs and the `SIG` record-type mapping bug.

## Red ledger (initial baseline)

`ci-data/test_status.baseline` records the exact set of expected failures. It
must be matched exactly in later phases: any new failure is a regression, and a
fixed test must be removed from the baseline.

| Test | Phase | Reason |
| --- | --- | --- |
| `LibraryTest.ParseTxtReplyOK` | 2 (DNS) | `ares_parse_txt_reply` merges all character-strings of a TXT RR into one node instead of one node per string. |
| `LibraryTest.ParseTxtEmpty` | 2 (DNS) | `ares_dns_rr_get_abin_cnt()` returns 0 for an empty TXT RR instead of one zero-length character-string. |
| `LibraryTest.DNSMapping` | 2 (DNS) | `SIG` (24) round-trips through `ares_dns_rec_type_tostr/fromstr` as `A` (16). |
| `AddressFamilies/MockUDPMaxQueriesTest.GetHostByNameParallelLookups/ipv4` | 4A (transport) | `ARES_OPT_UDP_MAX_QUERIES` is not enforced; 32 parallel lookups run with a limit of 8. |
| `AddressFamilies/MockUDPMaxQueriesTest.GetHostByNameParallelLookups/ipv6` | 4A (transport) | Same as above for IPv6. |

Top failing groups by phase: phase 2 (DNS/TXT and record-type mapping) accounts
for 3 failures; phase 4A (UDP transport concurrency) accounts for 2.

## Uncertainty / notes

- The Linux `select()` warnings printed by the original c-ares run are from the
  library’s own live tests; they are non-fatal and the run still exits 0.
- The original c-ares build was reused from `/tmp/cares-build` as permitted by
  the task, and rebuilt to confirm it matches `/home/user/c-ares-1.34.6`.
- Deferred tests are absent from the 526-test count. They are listed in the
  provenance manifest with category and owning phase; they are not silently
  dropped.
- `ci-data/exports.baseline` and `ci-data/cares.h.baseline` were not modified.
