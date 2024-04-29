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

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if target_arch == "x86_64" && target_os == "android" {
        let android_home = std::env::var("ANDROID_HOME").expect("ANDROID_HOME not set");
        const ANDROID_NDK_VERSION: &str = "25.2.9519653";
        const LINUX_X86_64_LIB_DIR: &str = "/toolchains/llvm/prebuilt/linux-x86_64/lib64/clang/14.0.7/lib/linux/";
        println!("cargo:rustc-link-search={android_home}/ndk/{ANDROID_NDK_VERSION}/{LINUX_X86_64_LIB_DIR}");
        println!("cargo:rustc-link-lib=static=clang_rt.builtins-x86_64-android");
    }
}
