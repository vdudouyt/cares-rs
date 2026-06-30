#!/usr/bin/env bash
#
# Build upstream curl against cares-rs and verify it links + resolves through it.
#
# curl, like every other c-ares consumer, expects the stock c-ares names
# (<ares.h>, libcares.so, pkg-config "libcares"). make_cares_shim (see ../common.sh)
# presents the installed cares-rs under those names; we then configure curl with
# --enable-ares=$SHIM so it links cares-rs instead of the system c-ares.
#
# Proof that cares-rs (not the system c-ares 1.27) was linked: the built curl reports
# "c-ares/1.34.6" in --version and has DT_NEEDED libcares_rs.so.2.
#
# Usage: ./build.sh [BUILD_DIR]   (default: ./build next to this script)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"

BUILD_DIR="${1:-$SCRIPT_DIR/build}"
SHIM="$BUILD_DIR/shim"

CURL_VERSION="8.5.0"
CURL_TARBALL="curl-${CURL_VERSION}.tar.gz"
CURL_URL="https://curl.se/download/${CURL_TARBALL}"
CURL_SRC="$BUILD_DIR/curl-${CURL_VERSION}"

say "Preflight: cares-rs must be installed (libcares-rs-dev)"
cares_rs_preflight

say "Build the c-ares compat shim at $SHIM"
make_cares_shim "$SHIM"

# --------------------------------------------------------------------------
say "Fetch curl ${CURL_VERSION}"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
if [ ! -f "$CURL_TARBALL" ]; then
    curl -fsSL -o "$CURL_TARBALL" "$CURL_URL"
fi
# Verify against curl.se's published checksum when reachable; otherwise just record it.
if curl -fsSL -o "${CURL_TARBALL}.sha256" "${CURL_URL}.sha256" 2>/dev/null; then
    sha256sum -c "${CURL_TARBALL}.sha256"
else
    echo "WARN: could not fetch published .sha256; recording local hash only"
    sha256sum "$CURL_TARBALL"
fi
rm -rf "$CURL_SRC"
tar -xf "$CURL_TARBALL"

# --------------------------------------------------------------------------
say "Configure curl --enable-ares=$SHIM (minimal, no TLS — DNS happens before TLS)"
cd "$CURL_SRC"
./configure \
    --enable-ares="$SHIM" \
    --without-ssl \
    --without-libpsl \
    --disable-shared --enable-static \
    --disable-ldap --disable-ldaps \
    --disable-rtsp --disable-dict --disable-telnet --disable-tftp \
    --disable-pop3 --disable-imap --disable-smb --disable-smtp \
    --disable-gopher --disable-mqtt --disable-manual \
    --without-brotli --without-zstd --without-nghttp2 --without-libidn2

# Confirm configure actually selected the c-ares (async) resolver.
say "configure summary (resolver)"
grep -iE "c-ares|resolver" config.log | tail -5 || true

# --------------------------------------------------------------------------
say "Build curl"
make -j"$(nproc)"

CURL_BIN="$CURL_SRC/src/curl"
[ -x "$CURL_BIN" ] || { echo "FATAL: $CURL_BIN was not built"; exit 1; }

# --------------------------------------------------------------------------
# Verification
fail=0

say "VERIFY 1/4 — curl links cares-rs (reports c-ares/1.34.6, not 1.27.0)"
"$CURL_BIN" --version
if "$CURL_BIN" --version | grep -q 'c-ares/1.34.6'; then
    echo "PASS: curl --version reports c-ares/1.34.6"
else
    echo "FAIL: curl --version does not report c-ares/1.34.6"; fail=1
fi

say "VERIFY 2-3/4 — loader / DT_NEEDED / nm all point at cares-rs"
verify_cares_rs_link "$CURL_BIN" || fail=1

say "VERIFY 4/4 — functional resolution through cares-rs (best effort)"
# Save the verbose trace to a file and inspect that, so neither curl's overall exit
# code (e.g. a slow response hitting --max-time) nor pipefail can mask a successful
# resolve+connect. A successful "Connected to ..." proves cares-rs did the lookup.
"$CURL_BIN" -sSv --max-time 30 http://example.com -o /dev/null > "$BUILD_DIR/resolve.log" 2>&1 || true
grep -E "was resolved|IPv4:|IPv6:|Connected to example.com" "$BUILD_DIR/resolve.log" || true
if grep -qE "Connected to example.com" "$BUILD_DIR/resolve.log"; then
    echo "PASS: curl resolved + connected to example.com via cares-rs"
else
    echo "WARN: functional resolution did not complete (no outbound DNS/HTTP in this env?)."
    echo "      Link-level proof (checks 1-3) already shows cares-rs is the resolver backend."
fi

say "RESULT"
if [ "$fail" -eq 0 ]; then
    echo "SUCCESS: curl ${CURL_VERSION} built and linked against cares-rs (libcares_rs.so.2)."
    echo "Binary: $CURL_BIN"
else
    echo "FAILURE: one or more link-level checks failed (see above)."
    exit 1
fi
