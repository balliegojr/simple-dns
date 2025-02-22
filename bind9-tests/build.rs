use std::env;
use std::path::PathBuf;

use bindgen::Builder;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");

    println!("cargo:rustc-link-lib=dns");
    println!("cargo:rustc-link-lib=isc");
    println!("cargo:rustc-link-lib=atomic");

    let builder = get_bindings_builder();
    let bindings = builder.generate().expect("Failed to generate bindings");

    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings");
}

fn get_bindings_builder() -> Builder {
    bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
}
