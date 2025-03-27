fn main() {
    #[cfg(target_family = "wasm")]
    println!("cargo:rustc-cfg=wasm");

    #[cfg(target_os = "ios")]
    println!("cargo:rustc-cfg=ios");
}
