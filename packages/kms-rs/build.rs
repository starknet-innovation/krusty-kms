use std::{env, path::PathBuf};

fn main() {
    let lib_dir = match env::var("KMS_LIB_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => {
            let manifest_dir =
                PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
            manifest_dir
                .parent()
                .and_then(|p| p.parent())
                .expect("workspace root")
                .join("target")
                .join("release")
        }
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=kms");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=KMS_LIB_DIR");
}
