use std::{env, path::PathBuf, process::Command};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let object = out.join("snapshot.o");
    let library = out.join("libsnapshot.a");
    assert!(
        Command::new("cc")
            .args([
                "-std=c11",
                "-O2",
                "-fomit-frame-pointer",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-c",
                "snapshot.c",
                "-o"
            ])
            .arg(&object)
            .status()
            .expect("run cc")
            .success(),
        "compile snapshot helper"
    );
    assert!(
        Command::new("ar")
            .arg("crs")
            .arg(&library)
            .arg(&object)
            .status()
            .expect("run ar")
            .success(),
        "archive snapshot helper"
    );
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=snapshot");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rerun-if-changed=snapshot.c");
}
