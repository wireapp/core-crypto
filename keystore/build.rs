fn main() {
    #[cfg(target_os = "unknown")]
    println!("cargo:rustc-cfg=wasm");

    #[cfg(target_os = "ios")]
    println!("cargo:rustc-cfg=ios");
}
