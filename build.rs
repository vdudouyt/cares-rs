use std::env;
use std::path::PathBuf;

// Generate include/cares.h with cbindgen on every build so it can't drift from
// the .so; the header is a git-ignored build artifact.
fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    println!("cargo:rerun-if-changed=src/ffi");
    // cbindgen parses the whole crate; core defines types the ffi signatures reference.
    println!("cargo:rerun-if-changed=src/core");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
    // Watch the output so deletion/tampering re-triggers generation; cbindgen only
    // rewrites on content change, so an unchanged regen doesn't cause a rebuild loop.
    println!("cargo:rerun-if-changed=include/cares.h");

    let config = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml"))
        .expect("read cbindgen.toml");

    let bindings = match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(b) => b,
        // Warn instead of failing the build if header generation hiccups.
        Err(e) => {
            println!("cargo:warning=cbindgen header generation failed: {e}");
            return;
        }
    };

    // include/ is git-ignored; create it for fresh checkouts (write_to_file only
    // rewrites when contents change, so mtimes stay untouched).
    let include_dir = crate_dir.join("include");
    let _ = std::fs::create_dir_all(&include_dir);
    bindings.write_to_file(include_dir.join("cares.h"));
}
