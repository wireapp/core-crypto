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

use vergen_gitcl::{BuildBuilder, CargoBuilder, Emitter, GitclBuilder};

fn main() -> anyhow::Result<()> {
    // Target aliases
    #[cfg(target_os = "ios")]
    println!("cargo:rustc-cfg=ios");

    #[cfg(target_family = "wasm")]
    println!("cargo:rustc-cfg=wasm");

    #[cfg(target_os = "android")]
    println!("cargo:rustc-cfg=android");

    if let Ok(profile) = std::env::var("PROFILE") {
        println!("cargo:rustc-cfg=build=\"{profile}\"");
    }

    // collect a bunch of build/git information and emit it into the build environment,
    // from whence we can extract it and make it public
    let build = BuildBuilder::default().build_timestamp(true).build()?;
    let cargo = CargoBuilder::default()
        .debug(true)
        .features(true)
        .opt_level(true)
        .target_triple(true)
        .build()?;
    let git = GitclBuilder::default()
        .branch(true)
        .sha(false)
        .dirty(false)
        .describe(true, true, Some("v*"))
        .build()?;

    Emitter::default()
        .fail_on_error()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        .add_instructions(&git)?
        .emit()?;

    Ok(())
}
