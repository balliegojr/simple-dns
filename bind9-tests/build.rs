use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");

    println!("cargo:rustc-link-lib=dns");
    println!("cargo:rustc-link-lib=isc");
    println!("cargo:rustc-link-lib=atomic");

    generate_bindings(&out_path);
}

fn generate_bindings(out_path: &Path) {
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings");
}
