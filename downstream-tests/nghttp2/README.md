# Downstream test: nghttp2 built against cares-rs

This builds **nghttp2** from its upstream release tarball, linked against **cares-rs**
instead of the system c-ares, and verifies that its c-ares–using application — **nghttpx**
— links and runtime-loads cares-rs.

It is the second project for the Stage-2 spec item *"build 2–3 projects from the Debian
repository that depend on c-ares against cares-rs"* (curl is the first; see `../curl/`).

## Run it

```sh
./build.sh [BUILD_DIR]      # default BUILD_DIR: ./build
```

Requires `libcares-rs-dev` + `libcares-rs2`, a C/C++ toolchain (`gcc`, `g++`, `make`),
and the nghttp2 app dependencies **OpenSSL**, **zlib** and **libev** (`libssl-dev`,
`zlib1g-dev`, `libev-dev`). The compat-shim mechanism is shared with the curl test
(`../common.sh`, `make_cares_shim`).

## How it works

nghttp2's **core library does not use c-ares** — only its applications do. The c-ares
consumer is **nghttpx**'s dynamic DNS resolver (`src/shrpx_dns_resolver.cc`), which calls
`ares_init_options`, `ares_gethostbyname`, `ares_process_fd`, `ares_timeout`,
`ares_destroy`, `ares_strerror`, `ares_library_init/cleanup`.

nghttp2 detects c-ares purely through pkg-config:
`PKG_CHECK_MODULES([LIBCARES], [libcares >= 1.7.5])`. Both stock c-ares (1.27) and the
shim (cares-rs, 1.34.6) satisfy `>= 1.7.5`, so the script puts the shim **first** on
`PKG_CONFIG_PATH` to shadow the stock module, and passes `--with-libcares` to make c-ares
**mandatory** — a successful configure+build therefore proves cares-rs was found and used.
As with curl, the shim's `libcares.pc` keeps `-lcares_rs`, so nghttpx records
`DT_NEEDED libcares_rs.so.2` and the loader picks up the installed cares-rs at run time.

No cares-rs source is modified.

## Recorded results

Built against **nghttp2 1.59.0** (matching the system package version;
`sha256 90fd27685120404544e96a60ed40398a3457102840c38e7215dc6dec8684470f`) and cares-rs
`0.1.0` / ABI `1.34.6`.

configure resolved c-ares to the shim (cares-rs):

```
pkg-config resolves libcares -> 1.34.6 (-lcares_rs)
LIBCARES_CFLAGS='-I.../shim/include'
LIBCARES_LIBS='-lcares_rs'
```

Of the four built apps, only **nghttpx** uses c-ares:

```
nghttpx: links libcares_rs.so.2
nghttp:  (no c-ares)
nghttpd: (no c-ares)
h2load:  (no c-ares)
```

Verification (both checks pass):

```
VERIFY 1/2 — nghttpx runs (runtime-loads + binds cares-rs symbols)
  nghttpx nghttp2/1.59.0
  PASS  (executing --version maps every DT_NEEDED lib and binds its symbols; a missing
         ares_* symbol would abort process startup)

VERIFY 2/2 — loader / DT_NEEDED / nm
  libcares_rs.so.2 => /lib/x86_64-linux-gnu/libcares_rs.so.2
  NEEDED  libcares_rs.so.2
  PASS: ldd shows libcares_rs.so.2 / stock libcares.so.2 not linked
  PASS: DT_NEEDED libcares_rs.so.2
  PASS: all 8 ares_* imports provided by cares-rs
        (ares_init_options, ares_gethostbyname, ares_process_fd, ares_timeout,
         ares_destroy, ares_strerror, ares_library_init, ares_library_cleanup)
```

## Notes

- Optional nghttp2 features (libxml2, jansson, systemd, mruby, HTTP/3) are disabled to
  keep dependencies light; none affect the c-ares path.
- Unlike curl, an end-to-end functional DNS test isn't trivially scriptable here:
  nghttpx's c-ares resolver only runs as part of proxying live traffic to a hostname
  backend. The link + runtime-load proof (cares-rs maps and all `ares_*` symbols bind
  when nghttpx starts) is what this test establishes; the curl test (`../curl/`) already
  demonstrates cares-rs performing real A+AAAA resolution end-to-end.
- The fetched source and build tree live under `BUILD_DIR` (default `./build/`,
  git-ignored).
