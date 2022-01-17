fn main() {
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
}
