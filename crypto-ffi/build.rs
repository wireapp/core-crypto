const UDL_FILE: &str = "./src/CoreCrypto.udl";

fn main() {
    // Target aliases
    #[cfg(any(
        target = "aarch64-apple-ios",
        target = "aarch64-apple-ios-sim",
        target = "x86_64-apple-ios",
    ))]
    println!("cargo:rustc-cfg=ios");

    #[cfg(any(
        target = "wasm32-unknown-unknown",
        target = "wasm32-wasi",
        target = "wasm32-unknown-emscripten"
    ))]
    println!("cargo:rustc-cfg=wasm");

    #[cfg(any(
        target = "aarch64-linux-android",
        target = "arm-linux-androideabi",
        target = "armv7-linux-androideabi",
        target = "i686-linux-android",
        target = "thumbv7neon-linux-androideabi",
        target = "x86_64-linux-android",
    ))]
    println!("cargo:rustc-cfg=android");

    uniffi_build::generate_scaffolding(UDL_FILE).unwrap();
    uniffi_bindgen::generate_bindings(UDL_FILE, None, vec!["kotlin"], Some("./bindings/kt/"), false).unwrap();
    uniffi_bindgen::generate_bindings(UDL_FILE, None, vec!["swift"], Some("./bindings/swift/"), false).unwrap();
}
