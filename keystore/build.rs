#[cfg(target = "aarch64-apple-ios")]
fn main() {
    if !cfg(feature = "ios-wal-compat") {
        panic!("Please enable the `ios-wal-compat` feature otherwise the keystore might not function properly");
    }
}

#[cfg(not(target = "aarch64-apple-ios"))]
fn main() {}
