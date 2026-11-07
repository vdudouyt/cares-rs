#!/usr/bin/env bash
#
# Build upstream nghttp2 against cares-rs and verify its app (nghttpx) links cares-rs.
#
# nghttp2's core library does not use c-ares; its applications do — specifically
# nghttpx's dynamic DNS resolver (src/shrpx_dns_resolver.cc), which calls
# ares_init_options / ares_gethostbyname / ares_process_fd / ares_timeout / ares_destroy.
# nghttp2 detects c-ares with pkg-config: PKG_CHECK_MODULES([libcares >= 1.7.5]).
#
# We reuse the same compat shim as the curl test (see ../common.sh) and put it first on
# PKG_CONFIG_PATH so the shim's libcares (cares-rs, 1.34.6) shadows the stock one (1.27).
# --with-libcares makes c-ares mandatory, so a successful build proves it was found+used.
#
# Usage: ./build.sh [BUILD_DIR]   (default: ./build next to this script)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"

BUILD_DIR="${1:-$SCRIPT_DIR/build}"
SHIM="$BUILD_DIR/shim"

NGHTTP2_VERSION="1.59.0"
NGHTTP2_TARBALL="nghttp2-${NGHTTP2_VERSION}.tar.gz"
NGHTTP2_URL="https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VERSION}/${NGHTTP2_TARBALL}"
NGHTTP2_SRC="$BUILD_DIR/nghttp2-${NGHTTP2_VERSION}"

say "Preflight: cares-rs must be installed (libcares-rs-dev)"
cares_rs_preflight
# App deps (nghttp2's c-ares user, nghttpx, also needs these):
for dep in libev openssl zlib; do
    pkg-config --exists "$dep" 2>/dev/null || \
        echo "NOTE: pkg-config can't see '$dep' directly (libev has no .pc; checked another way)"
done

say "Build the c-ares compat shim at $SHIM"
make_cares_shim "$SHIM"

# --------------------------------------------------------------------------
say "Fetch nghttp2 ${NGHTTP2_VERSION}"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
if [ ! -f "$NGHTTP2_TARBALL" ]; then
    curl -fsSL -o "$NGHTTP2_TARBALL" "$NGHTTP2_URL"
fi
# GitHub release assets have no companion .sha256; record the hash for reproducibility.
echo "tarball sha256: $(sha256sum "$NGHTTP2_TARBALL" | awk '{print $1}')"
rm -rf "$NGHTTP2_SRC"
tar -xf "$NGHTTP2_TARBALL"

# --------------------------------------------------------------------------
say "Configure nghttp2 --enable-app --with-libcares (shim first on PKG_CONFIG_PATH)"
cd "$NGHTTP2_SRC"
export PKG_CONFIG_PATH="$SHIM/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
echo "pkg-config resolves libcares -> $(pkg-config --modversion libcares) ($(pkg-config --libs libcares))"
./configure \
    --enable-app \
    --with-libcares \
    --enable-static --disable-shared \
    --disable-python-bindings \
    --without-libxml2 --without-jansson --without-systemd \
    --without-mruby --without-neverbleed \
    --without-libngtcp2 --without-libnghttp3

# Confirm configure actually picked up c-ares.
say "configure summary (c-ares / apps)"
grep -iE "libcares|Applications:|c-ares" config.log | tail -8 || true

# --------------------------------------------------------------------------
say "Build nghttp2 (lib + apps)"
make -j"$(nproc)"

NGHTTPX_BIN="$NGHTTP2_SRC/src/nghttpx"
[ -x "$NGHTTPX_BIN" ] || { echo "FATAL: $NGHTTPX_BIN was not built (apps disabled?)"; exit 1; }

# --------------------------------------------------------------------------
# Verification
fail=0

say "Built binaries that link cares-rs"
for b in "$NGHTTP2_SRC"/src/nghttpx "$NGHTTP2_SRC"/src/nghttp "$NGHTTP2_SRC"/src/nghttpd "$NGHTTP2_SRC"/src/h2load; do
    [ -x "$b" ] || continue
    if objdump -p "$b" 2>/dev/null | grep -q 'NEEDED.*libcares_rs.so.2'; then
        echo "  $(basename "$b"): links libcares_rs.so.2"
    else
        echo "  $(basename "$b"): (no c-ares)"
    fi
done

say "VERIFY 1/2 — nghttpx runs (runtime-loads + binds cares-rs symbols)"
# Executing --version forces the loader to map every DT_NEEDED lib (incl. cares-rs) and
# bind its symbols; if any ares_* symbol were missing the process would fail to start.
if "$NGHTTPX_BIN" --version; then
    echo "PASS: nghttpx --version ran (cares-rs loaded + symbols resolved at runtime)"
else
    echo "FAIL: nghttpx --version failed to run"; fail=1
fi

say "VERIFY 2/2 — loader / DT_NEEDED / nm all point at cares-rs"
verify_cares_rs_link "$NGHTTPX_BIN" || fail=1

say "RESULT"
if [ "$fail" -eq 0 ]; then
    echo "SUCCESS: nghttp2 ${NGHTTP2_VERSION} (nghttpx) built and linked against cares-rs (libcares_rs.so.2)."
    echo "Binary: $NGHTTPX_BIN"
else
    echo "FAILURE: one or more link-level checks failed (see above)."
    exit 1
fi
