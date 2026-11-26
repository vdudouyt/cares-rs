# Downstream drop-in tests

Real-world projects that depend on **c-ares**, rebuilt from upstream source against
**cares-rs** to prove it is a drop-in replacement for the c-ares 1.34 C ABI. This covers
the Stage-2 spec item *"build 2–3 projects from the Debian repository that depend on
c-ares against cares-rs"*.

| project | c-ares user | detection | status |
|---|---|---|---|
| [`curl/`](curl/) | the `curl`/`libcurl` resolver backend | `--enable-ares=$SHIM` | ✅ links + **resolves** (A+AAAA) end-to-end |
| [`nghttp2/`](nghttp2/) | `nghttpx` dynamic DNS resolver | `pkg-config libcares` (`--with-libcares`) | ✅ links + runtime-loads cares-rs |

## The shared mechanism

cares-rs ships the c-ares 1.34 ABI under the stock names: header `<ares.h>`, library
`libcares.so.2`, and pkg-config module `libcares`. Downstream consumers therefore need
no renaming to build against it. [`common.sh`](common.sh)'s `make_cares_shim` still
builds a throwaway prefix that pins header/library/pkg-config lookups to the *installed*
cares-rs files, so a distro c-ares cannot shadow them. Each consumer's binary records
`DT_NEEDED libcares.so.2` and resolves to the installed cares-rs at run time — no
`LD_LIBRARY_PATH`.

Because both projects are now called `libcares.so`, name-only checks are ambiguous.
`common.sh` provides `verify_cares_rs_link`, which compares the loader's **resolved path**
with the installed cares-rs object in addition to `DT_NEEDED` and the `nm` symbol check.

**No cares-rs source is changed** — it already exports the full c-ares 1.34 ABI
(126 `ares_*` symbols), so these are pure integration tests.

## Running

Each project is self-contained:

```sh
./curl/build.sh        # or:  ./curl/build.sh /some/build/dir
./nghttp2/build.sh
```

Prerequisite: the cares-rs Debian packages (`libcares-rs-dev`, `libcares-rs2`) installed.
Fetched sources and build trees go under each project's `build/` (git-ignored).
