fn main() {
    // Target aliases
    #[cfg(target_os = "ios")]
    println!("cargo:rustc-cfg=ios");

    #[cfg(target_family = "wasm")]
    println!("cargo:rustc-cfg=wasm");

    #[cfg(target_os = "android")]
    println!("cargo:rustc-cfg=android");
}
