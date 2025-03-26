fn main() {
    #[cfg(target_family = "wasm")]
    println!("cargo:rustc-cfg=wasm");

    #[cfg(target_os = "ios")]
    println!("cargo:rustc-cfg=ios");

    if cfg!(all(target_os = "ios", not(feature = "ios-wal-compat"))) {
        panic!("Please enable the `ios-wal-compat` feature otherwise the keystore might not function properly");
    }
}
