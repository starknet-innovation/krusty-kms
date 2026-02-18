use std::{env, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();

    let default_lib_dir = root.join("zig").join("zig-out").join("lib");
    println!("cargo:rustc-link-search=native={}", default_lib_dir.display());
    println!("cargo:rustc-link-lib=kms");
    println!(
        "cargo:rustc-link-arg=-Wl,-rpath,{}",
        default_lib_dir.display()
    );

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", root.join("zig/include/kms.h").display());
}
