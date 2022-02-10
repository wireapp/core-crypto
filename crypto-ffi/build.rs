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
