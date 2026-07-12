# Downstream test: curl built against cares-rs

This builds the canonical c-ares consumer — **curl** — from its upstream release
tarball, linked against **cares-rs** instead of the system c-ares, and verifies that
curl's asynchronous DNS resolution runs through cares-rs end-to-end.

It satisfies the Stage-2 spec item *"build 2–3 projects from the Debian repository that
depend on c-ares against cares-rs"* — curl is the first such project.

## Run it

```sh
./build.sh [BUILD_DIR]      # default BUILD_DIR: ./build
```

Requires `libcares-rs-dev` + `libcares-rs2` installed (the cares-rs Debian packages),
plus a C toolchain (`gcc`, `make`). No TLS libraries are needed — the build disables TLS
because DNS resolution happens before any TLS handshake.

## How it works — the c-ares compat shim

cares-rs exposes the full c-ares 1.34 C ABI, but ships under its own names so it can be
installed alongside the real c-ares:

| | stock c-ares | cares-rs |
|---|---|---|
| header | `<ares.h>` | `<cares-rs/ares.h>` |
| library / SONAME | `libcares.so.2` | `libcares_rs.so.2` |
| pkg-config module | `libcares` | `libcares-rs` |

curl (like every c-ares consumer) looks for the **stock** names. `build.sh` therefore
creates a throwaway *compat shim* prefix that presents the installed cares-rs under the
stock names, then configures curl with `--enable-ares=$SHIM`:

```
$SHIM/include/ares.h            -> symlink -> /usr/include/cares-rs/ares.h
$SHIM/include/ares_*.h          -> stub `#include <ares.h>` (cares-rs's header is self-contained)
$SHIM/lib/libcares.so           -> symlink -> /usr/lib/<triplet>/libcares_rs.so
$SHIM/lib/pkgconfig/libcares.pc -> Name: c-ares / Version: 1.34.6 / Libs: -lcares_rs
```

The shim's `libcares.pc` keeps `Libs: -lcares_rs`, so the linker records
`DT_NEEDED libcares_rs.so.2` in the curl binary — at run time the loader picks up the
system-installed cares-rs with **no** `LD_LIBRARY_PATH` needed. Pointing curl explicitly
at `$SHIM` (rather than the system pkg-config path) also guarantees the stock
`libcares.pc` (c-ares 1.27, also installed here) can't shadow it. The **c-ares version
string is the discriminator**: stock would report `1.27.0`, cares-rs reports `1.34.6`.

No cares-rs source is modified — cares-rs already exports all 16 `ares_*` functions
curl's `lib/asyn-ares.c` calls, and its generated header declares everything curl
compiles against (`ARES_VERSION*`, `ares_channel`, `ares_getaddrinfo`, `ares_dup`, …).

## Recorded results

Built against **curl 8.5.0** (`sha256 05fc17ff25b793a437a0906e0484b82172a9f4de02be5ed447e0cab8c3475add`,
verified against curl.se's published checksum) and cares-rs `0.1.0` / ABI `1.34.6`.

curl's `configure` selected the c-ares backend:

```
checking whether to enable c-ares for DNS lookups... yes
checking that c-ares is good and recent enough... yes
  resolver:         c-ares
USE_ARES='1'
```

All four verification checks pass:

```
VERIFY 1/4 — curl --version reports the linked c-ares
  curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 zlib/1.3 c-ares/1.34.6
  Features: alt-svc AsynchDNS IPv6 Largefile libz threadsafe UnixSockets
  PASS  (c-ares/1.34.6 = cares-rs, not the system c-ares/1.27.0)

VERIFY 2/4 — loader resolves cares-rs
  libcares_rs.so.2 => /lib/x86_64-linux-gnu/libcares_rs.so.2
  PASS  (libcares_rs.so.2 present; stock libcares.so.2 absent)

VERIFY 3/4 — DT_NEEDED
  NEEDED  libcares_rs.so.2
  PASS

VERIFY 4/4 — functional resolution through cares-rs
  * Host example.com:80 was resolved.
  * IPv6: 2606:4700:10::6814:179a, 2606:4700:10::ac42:93f3
  * IPv4: 172.66.147.243, 104.20.23.154
  * Connected to example.com (172.66.147.243) port 80
  PASS  (dual-stack A+AAAA via ares_getaddrinfo; HTTP/1.1 200 OK)
```

VERIFY 4 exercises cares-rs's real query path: curl's c-ares backend issues `AF_UNSPEC`
`ares_getaddrinfo`, cares-rs returns merged A + AAAA records, and curl connects and gets
`200 OK` — confirming cares-rs is a working drop-in c-ares for a real downstream.

## Notes

- The build is intentionally minimal (`--without-ssl --without-libpsl`, most protocols
  disabled) to keep dependencies light; it does not affect the resolver path.
- The fetched curl source and build tree live under `BUILD_DIR` (default `./build/`,
  git-ignored) and are not committed.
- Next downstream (spec wants 2–3): **nghttp2** reuses the same shim
  (`--with-libcares`, `PKG_CHECK_MODULES([libcares >= 1.7.5])`).
