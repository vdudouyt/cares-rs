use std::env;
use std::path::PathBuf;

// Generate the public C header (`include/cares.h`) from the Rust FFI surface
// with cbindgen on every build, so the header can never drift from the `.so`
// (both derive from this crate's source). The header is a generated build
// artifact — it is git-ignored, not committed.
fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    println!("cargo:rerun-if-changed=src/ffi");
    // cbindgen parses the whole crate, and core defines types/logic the ffi
    // signatures reference — regenerate on core edits too.
    println!("cargo:rerun-if-changed=src/core");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
    // Watch the output too, so deleting/tampering with the header re-triggers
    // generation (cbindgen's write_to_file is content-conditional, so an
    // unchanged regen doesn't bump the mtime → no rebuild loop).
    println!("cargo:rerun-if-changed=include/cares.h");

    let config = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml"))
        .expect("read cbindgen.toml");

    let bindings = match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(b) => b,
        // Don't fail the whole build if header generation hiccups; surface a warning.
        Err(e) => {
            println!("cargo:warning=cbindgen header generation failed: {e}");
            return;
        }
    };

    // The header lives in `include/`, which is git-ignored — create it (a fresh
    // checkout has no empty dirs) before writing. cbindgen's write_to_file only
    // rewrites when the contents change, so this won't needlessly touch mtimes.
    let include_dir = crate_dir.join("include");
    let _ = std::fs::create_dir_all(&include_dir);
    bindings.write_to_file(include_dir.join("cares.h"));
}
