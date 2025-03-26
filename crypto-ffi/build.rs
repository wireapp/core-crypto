fn main() {
    cfg_if::cfg_if! {
        if #[cfg(target_family = "wasm")] {
            println!("cargo:rustc-cfg=wasm");
        } else {
            #[cfg(target_os = "ios")]
            println!("cargo:rustc-cfg=ios");
            #[cfg(target_os = "android")]
            println!("cargo:rustc-cfg=android");
        }
    }
}
