#!/usr/bin/env bash
#
# Shared helpers for the downstream drop-in tests.
#
# cares-rs exposes the c-ares 1.34 C ABI but ships under its own names so it can be
# installed alongside stock c-ares:
#     header  <cares-rs/ares.h>   (stock: <ares.h>)
#     library libcares_rs.so.2    (stock: libcares.so.2)
#     pkgconf libcares-rs         (stock: libcares)
# Downstream consumers look for the stock names, so make_cares_shim() builds a throwaway
# prefix that presents the installed cares-rs under the stock names. Point the consumer's
# build at it (PKG_CONFIG_PATH / --with-...=$SHIM) and it links cares-rs instead of c-ares.

MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"
CARES_RS_LIBDIR="/usr/lib/${MULTIARCH}"
CARES_RS_HEADER="/usr/include/cares-rs/ares.h"
CARES_RS_SO="${CARES_RS_LIBDIR}/libcares_rs.so"
# Resolved real object (e.g. .../libcares_rs.so.2.0.0) for symbol inspection.
CARES_RS_SO_REAL="$(readlink -f "$CARES_RS_SO" 2>/dev/null || echo "$CARES_RS_SO")"

say() { printf '\n=== %s ===\n' "$*"; }

# Fail early unless libcares-rs-dev / libcares-rs2 are installed.
cares_rs_preflight() {
    [ -f "$CARES_RS_HEADER" ] || { echo "FATAL: $CARES_RS_HEADER not found (install libcares-rs-dev)"; exit 1; }
    [ -e "$CARES_RS_SO" ]     || { echo "FATAL: $CARES_RS_SO not found (install libcares-rs-dev)"; exit 1; }
    echo "cares-rs header: $CARES_RS_HEADER"
    echo "cares-rs lib:    $CARES_RS_SO -> $CARES_RS_SO_REAL"
}

# make_cares_shim <shim_dir>  — present cares-rs under the stock c-ares names.
make_cares_shim() {
    local shim="$1"
    rm -rf "$shim"
    mkdir -p "$shim/include" "$shim/lib/pkgconfig"

    # cares-rs's generated header is self-contained; expose it as <ares.h> and provide
    # defensive re-include stubs for the headers stock c-ares splits out.
    ln -sf "$CARES_RS_HEADER" "$shim/include/ares.h"
    local h
    for h in ares_version.h ares_dns_record.h ares_build.h ares_dns.h ares_nameser.h; do
        printf '#include <ares.h>\n' > "$shim/include/$h"
    done

    # Stock link name -> cares-rs object. Keep -lcares_rs in the .pc so the consumer's
    # binary records DT_NEEDED libcares_rs.so.2 (resolves to system cares-rs at runtime).
    ln -sf "$CARES_RS_SO" "$shim/lib/libcares.so"
    cat > "$shim/lib/pkgconfig/libcares.pc" <<EOF
libdir=${CARES_RS_LIBDIR}
includedir=${shim}/include

Name: c-ares
Description: cares-rs presented as c-ares (compat shim)
Version: 1.34.6
Libs: -L\${libdir} -lcares_rs
Cflags: -I\${includedir}
EOF
    echo "shim pkg-config (libcares): $(PKG_CONFIG_PATH="$shim/lib/pkgconfig" pkg-config --modversion --libs libcares)"
}

# verify_cares_rs_link <binary>  — common link-level proof (ldd / DT_NEEDED / nm).
# Prints PASS/FAIL lines; returns non-zero if any check fails.
verify_cares_rs_link() {
    local bin="$1" fail=0

    echo "-- ldd (ares) --"; ldd "$bin" | grep -i ares || true
    if ldd "$bin" | grep -q 'libcares_rs.so.2'; then echo "PASS: ldd shows libcares_rs.so.2"
    else echo "FAIL: libcares_rs.so.2 absent from ldd"; fail=1; fi
    if ldd "$bin" | grep -qE '/libcares\.so\.2'; then echo "FAIL: stock libcares.so.2 is linked"; fail=1
    else echo "PASS: stock libcares.so.2 not linked"; fi

    echo "-- DT_NEEDED (ares) --"; objdump -p "$bin" | grep NEEDED | grep -i ares || true
    if objdump -p "$bin" | grep -q 'NEEDED.*libcares_rs.so.2'; then echo "PASS: DT_NEEDED libcares_rs.so.2"
    else echo "FAIL: DT_NEEDED is not libcares_rs.so.2"; fail=1; fi

    # nm: every ares_* the binary imports is defined by cares-rs.
    local missing imports
    imports=$(nm -D -u "$bin" | grep -c ' ares_' || true)
    missing=$(comm -23 \
        <(nm -D -u "$bin" | awk '/ ares_/{print $NF}' | sort -u) \
        <(nm -D --defined-only "$CARES_RS_SO_REAL" | awk '/ T ares_/{print $NF}' | sort -u))
    if [ -z "$missing" ]; then echo "PASS: all $imports ares_* imports provided by cares-rs"
    else echo "FAIL: cares-rs does not provide: $missing"; fail=1; fi

    return $fail
}
