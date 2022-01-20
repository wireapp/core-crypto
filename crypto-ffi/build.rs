#[allow(dead_code)]
const UDL_FILE: &str = "./src/CoreCrypto.udl";

fn main() {
    // Target aliases
    #[cfg(all(feature = "uniffi", target_os = "ios"))]
    println!("cargo:rustc-cfg=ios");

    #[cfg(target_family = "wasm")]
    println!("cargo:rustc-cfg=wasm");

    #[cfg(all(feature = "uniffi", target_os = "android"))]
    println!("cargo:rustc-cfg=android");

    #[cfg(feature = "uniffi")]
    uniffi_build::generate_scaffolding(UDL_FILE).unwrap();
    #[cfg(feature = "uniffi")]
    uniffi_bindgen::generate_bindings(UDL_FILE, None, vec!["kotlin"], Some("./bindings/kt/"), false).unwrap();
    #[cfg(feature = "uniffi")]
    uniffi_bindgen::generate_bindings(UDL_FILE, None, vec!["swift"], Some("./bindings/swift/"), false).unwrap();
}
