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

use glob::glob;
use std::path::Path;

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

        let ndk_root_str = format!("{android_home}/ndk/{ANDROID_NDK_VERSION}");
        let ndk_root = Path::new(ndk_root_str.as_str());
        if !ndk_root.exists() {
            panic!("Error: Couldn't find NDK at path {ndk_root_str}. NDK {ANDROID_NDK_VERSION} is required")
        }

        let search_path = format!(
            "{}/toolchains/llvm/prebuilt/*/lib*/clang/*/lib/linux/",
            ndk_root.to_str().unwrap()
        );

        let results: Vec<_> = glob(search_path.as_str())
            .expect("Failed to read glob pattern")
            .filter_map(Result::ok)
            .collect();

        if results.len() != 1 {
            if results.is_empty() {
                panic!("Could not find the directory for x86_64 clang builtins in {ndk_root_str}. A directory structure like this is expected inside the NDK root directory: '/toolchains/llvm/prebuilt/*/lib*/clang/*/lib/linux/'")
            }
            let all_results = results
                .iter()
                .map(|result| {
                    let path = result.as_os_str().to_str().unwrap();
                    format!("  - {path}")
                })
                .collect::<Vec<String>>()
                .join("\n");
            panic!("Found more than one alternative for x86_64 clang builtins in {ndk_root_str}:\n{all_results}");
        }

        let linux_libs_dir = results.first().unwrap().to_str().unwrap();
        println!("cargo:rustc-link-search={linux_libs_dir}");
        println!("cargo:rustc-link-lib=static=clang_rt.builtins-x86_64-android");
    }
}
