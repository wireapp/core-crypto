const UDL_FILE: &str = "./src/CoreCrypto.udl";

fn main() {
    // Target aliases
    #[cfg(all(feature = "mobile", target_os = "ios"))]
    println!("cargo:rustc-cfg=ios");

    #[cfg(target_family = "wasm")]
    println!("cargo:rustc-cfg=wasm");

    #[cfg(all(feature = "mobile", target_os = "android"))]
    println!("cargo:rustc-cfg=android");

    #[cfg(target = "wasm32-unknown-emscripten")]
    Command::new("emcc")
        .args(&["-c ./support/gxx_personality_v0_stub.cpp"])
        .status()
        .unwrap();

    #[cfg(feature = "mobile")]
    uniffi_build::generate_scaffolding(UDL_FILE).unwrap();
    #[cfg(feature = "mobile")]
    uniffi_bindgen::generate_bindings(UDL_FILE, None, vec!["kotlin"], Some("./bindings/kt/"), false).unwrap();
    #[cfg(feature = "mobile")]
    uniffi_bindgen::generate_bindings(UDL_FILE, None, vec!["swift"], Some("./bindings/swift/include"), false).unwrap();
    if cfg!(feature = "mobile") {
        std::fs::rename(
            "./bindings/swift/include/CoreCrypto.swift",
            "./bindings/swift/Sources/CoreCryptoSwift/CoreCryptoSwift.swift",
        )
        .unwrap();
    }
}
