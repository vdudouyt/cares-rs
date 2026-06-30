use std::env;
use std::path::PathBuf;

// Generate the public C header (`cares.h`) from the Rust FFI surface with cbindgen,
// so the shipped header can never drift from the shipped `.so` (both derive from
// this crate's source). Always emitted to OUT_DIR; the committed, reviewable copy
// at `include/cares.h` is refreshed only when CARES_REGEN_HEADER is set, so a
// normal `cargo build` / `cargo package` never mutates the working tree.
fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    println!("cargo:rerun-if-changed=src/ffi");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARES_REGEN_HEADER");

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

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_dir.join("cares.h"));

    if env::var_os("CARES_REGEN_HEADER").is_some() {
        bindings.write_to_file(crate_dir.join("include").join("cares.h"));
    }
}
