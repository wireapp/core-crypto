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
