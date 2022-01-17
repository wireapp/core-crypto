fn main() {
    #[cfg(any(
        target = "aarch64-apple-ios",
        target = "aarch64-apple-ios-sim",
        target = "x86_64-apple-ios",
    ))]
    println!("cargo:rustc-cfg=ios");

    if cfg!(all(ios, not(feature = "ios-wal-compat"))) {
        panic!("Please enable the `ios-wal-compat`, feature otherwise the keystore might not function properly");
    }
}
