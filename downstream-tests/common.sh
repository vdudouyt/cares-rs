#!/usr/bin/env bash
#
# Shared helpers for the downstream drop-in tests.
#
# cares-rs installs the stock c-ares names, so consumers need no renaming:
#     header  <ares.h>          (stock c-ares: <ares.h>)
#     library libcares.so.2     (stock c-ares: libcares.so.2)
#     pkgconf libcares          (stock c-ares: libcares)
# make_cares_shim() still builds a throwaway prefix that pins every lookup to the
# installed cares-rs files and stops a distro c-ares from shadowing them. Point the
# consumer's build at it (PKG_CONFIG_PATH / --with-...=$SHIM).
#
# Both libraries now share the same basename, so every verification compares the
# *resolved object path* against the installed cares-rs object. Checking only
# DT_NEEDED/libcares.so.2 would also pass when the binary loaded stock c-ares.

MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"
CARES_RS_LIBDIR="/usr/lib/${MULTIARCH}"
CARES_RS_HEADER="/usr/include/ares.h"
CARES_RS_SO="${CARES_RS_LIBDIR}/libcares.so"
# Resolved real object (e.g. .../libcares.so.2.0.0) for identity/symbol inspection.
CARES_RS_SO_REAL="$(readlink -f "$CARES_RS_SO" 2>/dev/null || echo "$CARES_RS_SO")"

say() { printf '\n=== %s ===\n' "$*"; }

# Fail early unless libcares-rs-dev / libcares-rs2 are installed.
cares_rs_preflight() {
    [ -f "$CARES_RS_HEADER" ] || { echo "FATAL: $CARES_RS_HEADER not found (install libcares-rs-dev)"; exit 1; }
    [ -e "$CARES_RS_SO" ]     || { echo "FATAL: $CARES_RS_SO not found (install libcares-rs-dev)"; exit 1; }
    echo "cares-rs header: $CARES_RS_HEADER"
    echo "cares-rs lib:    $CARES_RS_SO -> $CARES_RS_SO_REAL"
}

# make_cares_shim <shim_dir>  — pin the stock c-ares names to installed cares-rs.
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

    # Pin the stock link name to the installed cares-rs object. The .pc keeps
    # -lcares so the consumer records the stock SONAME, libcares.so.2.
    ln -sf "$CARES_RS_SO" "$shim/lib/libcares.so"
    cat > "$shim/lib/pkgconfig/libcares.pc" <<EOF
libdir=${CARES_RS_LIBDIR}
includedir=${shim}/include

Name: c-ares
Description: cares-rs presented as c-ares (compat shim)
Version: 1.34.6
Libs: -L\${libdir} -lcares
Cflags: -I\${includedir}
EOF
    echo "shim pkg-config (libcares): $(PKG_CONFIG_PATH="$shim/lib/pkgconfig" pkg-config --modversion --libs libcares)"
}

# ldd_resolved_ares <binary> — print the real path of the libcares.so.2 it loaded.
ldd_resolved_ares() {
    local bin="$1" path
    path=$(ldd "$bin" | awk '/libcares\.so\.2 =>/{print $3; exit}')
    [ -n "$path" ] && readlink -f "$path"
}

# verify_cares_rs_link <binary>  — common link-level proof (ldd / DT_NEEDED / nm).
# Prints PASS/FAIL lines; returns non-zero if any check fails.
verify_cares_rs_link() {
    local bin="$1" fail=0 resolved

    echo "-- ldd (ares) --"; ldd "$bin" | grep -i ares || true
    resolved="$(ldd_resolved_ares "$bin")"
    if [ -n "$resolved" ] && [ "$resolved" = "$CARES_RS_SO_REAL" ]; then
        echo "PASS: loader resolved libcares.so.2 to cares-rs ($resolved)"
    else
        echo "FAIL: libcares.so.2 resolves to '${resolved:-<not loaded>}', expected cares-rs ($CARES_RS_SO_REAL)"
        fail=1
    fi

    echo "-- DT_NEEDED (ares) --"; objdump -p "$bin" | grep NEEDED | grep -i ares || true
    if objdump -p "$bin" | grep -q 'NEEDED.*libcares\.so\.2'; then echo "PASS: DT_NEEDED libcares.so.2"
    else echo "FAIL: DT_NEEDED is not libcares.so.2"; fail=1; fi

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
