// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

#[allow(dead_code)]
const UDL_FILE: &str = "./src/CoreCrypto.udl";

fn main() {
    // Target aliases
    #[cfg(all(feature = "mobile", target_os = "ios"))]
    println!("cargo:rustc-cfg=ios");

    #[cfg(target_family = "wasm")]
    println!("cargo:rustc-cfg=wasm");

    #[cfg(all(feature = "mobile", target_os = "android"))]
    println!("cargo:rustc-cfg=android");

    #[cfg(feature = "mobile")]
    uniffi_build::generate_scaffolding(UDL_FILE).unwrap();
    #[cfg(feature = "mobile")]
    uniffi_bindgen::generate_bindings(
        UDL_FILE.into(),
        None,
        vec!["kotlin"],
        Some("./bindings/kt/".into()),
        false,
    )
    .unwrap();
    #[cfg(feature = "mobile")]
    uniffi_bindgen::generate_bindings(
        UDL_FILE.into(),
        None,
        vec!["swift"],
        Some("./bindings/swift/lib/".into()),
        false,
    )
    .unwrap();
    if cfg!(feature = "mobile") {
        std::fs::rename(
            "./bindings/swift/lib/CoreCrypto.swift",
            "./bindings/swift/Sources/CoreCryptoSwift/CoreCryptoSwift.swift",
        )
        .unwrap();
    }
}
