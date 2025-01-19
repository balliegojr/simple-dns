use std::env;
use std::path::PathBuf;

use bindgen::Builder;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");

    if cfg!(feature = "local-lib") {
        link_local("dns");
        link_local("isc");
    }

    println!("cargo:rustc-link-lib=dns");
    println!("cargo:rustc-link-lib=isc");
    println!("cargo:rustc-link-lib=atomic");

    let builder = get_bindings_builder();
    let bindings = builder.generate().expect("Failed to generate bindings");

    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings");
}

fn link_local(lib: &str) {
    let libdir_path = PathBuf::from(format!("../bind9/lib/{lib}/.libs"))
        .canonicalize()
        .expect("bind9 directory not found");

    println!("cargo:rustc-link-search={}", libdir_path.to_str().unwrap());
}

fn get_bindings_builder() -> Builder {
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    if cfg!(feature = "local-lib") {
        bindings
            .clang_arg("-I../bind9/lib/dns/include")
            .clang_arg("-I../bind9/lib/isc/include")
    } else {
        bindings
    }
}
