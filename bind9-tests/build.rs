use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bind9_dir = manifest_dir
        .join("../bind9")
        .canonicalize()
        .expect("bind9 directory not found — ensure the submodule is initialized");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");

    let dns_libs = bind9_dir.join("lib/dns/.libs");
    let isc_libs = bind9_dir.join("lib/isc/.libs");

    println!("cargo:rustc-link-search=native={}", dns_libs.display());
    println!("cargo:rustc-link-search=native={}", isc_libs.display());
    println!("cargo:rustc-link-lib=dns");
    println!("cargo:rustc-link-lib=isc");
    println!("cargo:rustc-link-lib=atomic");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dns_libs.display());
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", isc_libs.display());

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", bind9_dir.join("lib/dns/include").display()))
        .clang_arg(format!("-I{}", bind9_dir.join("lib/isc/include").display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Failed to generate bindings");

    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings");
}
