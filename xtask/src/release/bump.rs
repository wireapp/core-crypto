use color_eyre::eyre::{eyre, Result};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum BumpLevel {
    Major,
    Minor,
    Patch,
    Rc,
    Pre,
}

fn increment_pre_version(pre_kind: &str, pre: &semver::Prerelease) -> Result<semver::Prerelease> {
    let pre_str = pre.as_str();
    let components: Vec<&str> = pre_str.split('.').collect();

    let pre_kind_actual = components[0];
    let mut pre_target_version = 0;
    if pre_kind_actual == pre_kind {
        if components.len() == 2 {
            let pre_version: u64 = components[1].parse()?;
            pre_target_version = pre_version;
        } else {
            pre_target_version = 1;
        }
    }

    Ok(semver::Prerelease::new(&format!(
        "{pre_kind}.{}",
        pre_target_version + 1
    ))?)
}

fn bump_semver(bump_level: BumpLevel, old_version: &semver::Version) -> Result<semver::Version> {
    let mut version = old_version.clone();
    match bump_level {
        BumpLevel::Major => {
            version.major += 1;
            version.minor = 0;
            version.patch = 0;
            version.pre = semver::Prerelease::EMPTY;
            version.build = semver::BuildMetadata::EMPTY;
        }
        BumpLevel::Minor => {
            version.minor += 1;
            version.patch = 0;
            version.pre = semver::Prerelease::EMPTY;
            version.build = semver::BuildMetadata::EMPTY;
        }
        BumpLevel::Patch => {
            if version.pre.is_empty() {
                version.patch += 1;
            }
            version.pre = semver::Prerelease::EMPTY;
            version.build = semver::BuildMetadata::EMPTY;
        }
        BumpLevel::Rc => {
            version.pre = increment_pre_version("rc", &version.pre)?;
        }
        BumpLevel::Pre => {
            version.pre = increment_pre_version("pre", &version.pre)?;
        }
    }

    Ok(version)
}

fn bump_npm_version(bump_version: BumpLevel, dry_run: bool) -> Result<()> {
    let file = std::fs::File::open("./package.json")?;
    let reader = std::io::BufReader::new(file);

    let mut package_json: serde_json::Value = serde_json::from_reader(reader)?;

    let Some(package_name) = package_json["name"].as_str() else {
        return Err(eyre!("Cannot read package.json package name"));
    };

    let Some(former_version) = package_json["version"].as_str() else {
        return Err(eyre!("Version in package.json cannot be read"));
    };

    let semver_version = semver::Version::parse(former_version)?;

    let new_semver_version = bump_semver(bump_version, &semver_version)?;
    log::info!("Bumping NPM package {package_name}: {semver_version} -> {new_semver_version}");

    if !dry_run {
        package_json["version"] = new_semver_version.to_string().into();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("./package.json")?;
        serde_json::to_writer_pretty(&mut file, &package_json)?;
    }

    Ok(())
}

fn bump_gradle_version(file: &str, bump_version: BumpLevel, dry_run: bool) -> Result<()> {
    const SEARCH_STR: &str = "VERSION_NAME=";

    let mut gradle_build_file = std::fs::read_to_string(file)?;

    let Some((start_idx, end_idx)) = gradle_build_file
        .find(SEARCH_STR)
        .map(|idx| idx + SEARCH_STR.len())
        .and_then(|idx| gradle_build_file[idx..]
            .find('\n')
            .map(move |end_idx| (idx, end_idx + idx))
        ) else {
            return Err(eyre!("Could not find version in {}", file));
        };

    let semver_version = semver::Version::parse(&gradle_build_file[start_idx..end_idx])?;

    let new_semver_version = bump_semver(bump_version, &semver_version)?;
    log::info!("Bumping {file}: {semver_version} -> {new_semver_version}");

    if !dry_run {
        gradle_build_file.replace_range(start_idx..end_idx, &new_semver_version.to_string());
        std::fs::write(file, gradle_build_file)?;
        log::debug!("Wrote gradle file at {file}");
    }

    Ok(())
}

fn bump_gradle_versions(bump_version: BumpLevel, dry_run: bool) -> Result<()> {
    bump_gradle_version("./crypto-ffi/bindings/gradle.properties", bump_version, dry_run)?;
    Ok(())
}

fn bump_deps(
    package: &cargo::core::Package,
    manifest: &mut toml_edit::Document,
    ws_rust_dep_names_to_bump: &[&str],
    bump_version: BumpLevel,
    dry_run: bool,
) -> Result<()> {
    let package_name = package.name().as_str();
    for dep in package.dependencies() {
        // If it's a usual dependency, don't touch it
        let dep_name = dep.package_name().as_str();
        if !ws_rust_dep_names_to_bump.contains(&dep_name) {
            continue;
        }

        use cargo::core::dependency::DepKind;
        let dep_field = match dep.kind() {
            DepKind::Normal => "dependencies",
            DepKind::Development => "dev-dependencies",
            DepKind::Build => "build-dependencies",
        };

        use cargo::util::OptVersionReq;
        let required_version = match dep.version_req() {
            // No specific requirement, do nothing
            OptVersionReq::Any => {
                continue;
            }
            // Otherwise extract the requirement
            OptVersionReq::Req(req) | OptVersionReq::Locked(_, req) => req,
        };

        if required_version.comparators.is_empty() {
            log::warn!("[{package_name}.{dep_field}.{dep_name}] has an empty version requirement, skipping");
            continue;
        }

        let required_version_comparator = &required_version.comparators[0];
        let major = required_version_comparator.major;
        let minor = match required_version_comparator.minor {
            Some(minor_ver) => minor_ver,
            None if bump_version == BumpLevel::Minor => {
                log::info!("[{package_name}.{dep_field}.{dep_name}]: No requirement for current bump, skipping");
                continue;
            }
            None => {
                log::warn!("[{package_name}.{dep_field}.{dep_name}]: Empty minor requirement for current bump, you should double check the bump result, it will probably be incorrect");
                0
            }
        };
        let patch = match required_version_comparator.patch {
            Some(patch_ver) => patch_ver,
            None if bump_version == BumpLevel::Patch => {
                log::info!("[{package_name}.{dep_field}.{dep_name}]: No requirement for current bump, skipping");
                continue;
            }
            None => {
                log::warn!("[{package_name}.{dep_field}.{dep_name}]: Empty patch requirement for current bump, you should double check the bump result, it will probably be incorrect");
                0
            }
        };

        let pre = required_version_comparator.pre.clone();
        let required_version_semver = semver::Version {
            major,
            minor,
            patch,
            pre,
            build: semver::BuildMetadata::EMPTY,
        };

        let new_required_version_semver = bump_semver(bump_version, &required_version_semver)?;

        let mut new_required_version = required_version.clone();
        new_required_version.comparators[0].major = new_required_version_semver.major;
        new_required_version.comparators[0].minor = Some(new_required_version_semver.minor);
        new_required_version.comparators[0].patch = Some(new_required_version_semver.patch);
        new_required_version.comparators[0].pre = new_required_version_semver.pre;

        log::info!("Bumping [{package_name}.{dep_field}.{dep_name}]: {required_version} -> {new_required_version}");

        if !dry_run {
            if let Some(target) = dep.platform() {
                let target_table = manifest["target"][&target.to_string()][dep_field][dep_name]
                    .as_inline_table_mut()
                    .unwrap();
                let _ = target_table.insert_formatted(
                    &toml_edit::Key::new(toml_edit::InternalString::from("version")),
                    new_required_version.to_string().into(),
                );
            } else {
                manifest[dep_field][dep_name]["version"] = toml_edit::value(new_required_version.to_string());
            }
        }
    }

    Ok(())
}

pub fn bump(bump_version: BumpLevel, dry_run: bool) -> Result<()> {
    if dry_run {
        log::warn!("Dry run enabled, no actions will be performed on files");
    }

    let cargo_config = cargo::util::Config::default().map_err(|e| eyre!(e.to_string()))?;
    let ws = cargo::core::Workspace::new(&Path::new("./Cargo.toml").canonicalize()?, &cargo_config)
        .map_err(|e| eyre!(e.to_string()))?;

    let ws_rust_dep_names_to_bump: Vec<&str> = ws.members().map(|p| p.name().as_str()).collect();

    for package in ws.members() {
        let package_name = package.name();
        log::debug!("Found workspace member {package_name}");
        let manifest_path = package.manifest_path();
        log::debug!("Opening {manifest_path:?}...");
        let toml_raw_doc = std::fs::read_to_string(manifest_path)?;

        let mut manifest = toml_raw_doc.parse::<toml_edit::Document>()?;
        let semver_version = semver::Version::parse(
            manifest["package"]["version"]
                .as_str()
                .ok_or_else(|| eyre!("Could not parse version"))?,
        )?;

        let new_semver_version = bump_semver(bump_version, &semver_version)?;
        log::info!("Bumping Cargo package {package_name}: {semver_version} -> {new_semver_version}");

        bump_deps(
            package,
            &mut manifest,
            &ws_rust_dep_names_to_bump,
            bump_version,
            dry_run,
        )?;

        if !dry_run {
            manifest["package"]["version"] = toml_edit::value(new_semver_version.to_string());
            std::fs::write(manifest_path, manifest.to_string())?;
            log::debug!("Wrote new manifest");
        }
    }

    bump_npm_version(bump_version, dry_run)?;
    bump_gradle_versions(bump_version, dry_run)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bumps_major_version_correctly() {
        let version = semver::Version::parse("0.0.8").unwrap();
        let new_version = bump_semver(BumpLevel::Major, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.0.0");

        let version = semver::Version::parse("0.0.8-pre.4").unwrap();
        let new_version = bump_semver(BumpLevel::Major, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.0.0");

        let version = semver::Version::parse("0.0.8-rc.4").unwrap();
        let new_version = bump_semver(BumpLevel::Major, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.0.0");

        let version = semver::Version::parse("0.1.0-pre").unwrap();
        let new_version = bump_semver(BumpLevel::Major, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.0.0");

        let version = semver::Version::parse("0.1.1-pre.2").unwrap();
        let new_version = bump_semver(BumpLevel::Major, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.0.0");

        let version = semver::Version::parse("0.1.1").unwrap();
        let new_version = bump_semver(BumpLevel::Major, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.0.0");

        let version = semver::Version::parse("1.1.1-pre.1").unwrap();
        let new_version = bump_semver(BumpLevel::Major, &version).unwrap();
        assert_eq!(new_version.to_string(), "2.0.0");

        let version = semver::Version::parse("1.1.1").unwrap();
        let new_version = bump_semver(BumpLevel::Major, &version).unwrap();
        assert_eq!(new_version.to_string(), "2.0.0");

        let version = semver::Version::parse("1.0.0-rc.1").unwrap();
        let new_version = bump_semver(BumpLevel::Major, &version).unwrap();
        assert_eq!(new_version.to_string(), "2.0.0");
    }

    #[test]
    fn bumps_minor_version_correctly() {
        let version = semver::Version::parse("0.0.8").unwrap();
        let new_version = bump_semver(BumpLevel::Minor, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.0");

        let version = semver::Version::parse("0.0.8-pre.4").unwrap();
        let new_version = bump_semver(BumpLevel::Minor, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.0");

        let version = semver::Version::parse("0.0.8-rc.4").unwrap();
        let new_version = bump_semver(BumpLevel::Minor, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.0");

        let version = semver::Version::parse("0.1.0-pre").unwrap();
        let new_version = bump_semver(BumpLevel::Minor, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.2.0");

        let version = semver::Version::parse("0.1.1-pre.2").unwrap();
        let new_version = bump_semver(BumpLevel::Minor, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.2.0");

        let version = semver::Version::parse("0.1.1").unwrap();
        let new_version = bump_semver(BumpLevel::Minor, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.2.0");

        let version = semver::Version::parse("1.1.1-pre.1").unwrap();
        let new_version = bump_semver(BumpLevel::Minor, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.2.0");

        let version = semver::Version::parse("1.1.1").unwrap();
        let new_version = bump_semver(BumpLevel::Minor, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.2.0");

        let version = semver::Version::parse("1.0.0-rc.1").unwrap();
        let new_version = bump_semver(BumpLevel::Minor, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.1.0");
    }

    #[test]
    fn bumps_patch_version_correctly() {
        let version = semver::Version::parse("0.0.8").unwrap();
        let new_version = bump_semver(BumpLevel::Patch, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.0.9");

        let version = semver::Version::parse("0.0.8-pre.4").unwrap();
        let new_version = bump_semver(BumpLevel::Patch, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.0.8");

        let version = semver::Version::parse("0.0.8-rc.4").unwrap();
        let new_version = bump_semver(BumpLevel::Patch, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.0.8");

        let version = semver::Version::parse("0.1.0-pre").unwrap();
        let new_version = bump_semver(BumpLevel::Patch, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.0");

        let version = semver::Version::parse("0.1.1-pre.2").unwrap();
        let new_version = bump_semver(BumpLevel::Patch, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.1");

        let version = semver::Version::parse("0.1.1").unwrap();
        let new_version = bump_semver(BumpLevel::Patch, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.2");

        let version = semver::Version::parse("1.1.1-pre.1").unwrap();
        let new_version = bump_semver(BumpLevel::Patch, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.1.1");

        let version = semver::Version::parse("1.1.1").unwrap();
        let new_version = bump_semver(BumpLevel::Patch, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.1.2");

        let version = semver::Version::parse("1.0.0-rc.1").unwrap();
        let new_version = bump_semver(BumpLevel::Patch, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.0.0");
    }

    #[test]
    fn bumps_rc_version_correctly() {
        let version = semver::Version::parse("0.0.8").unwrap();
        let new_version = bump_semver(BumpLevel::Rc, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.0.8-rc.1");

        let version = semver::Version::parse("0.0.8-pre.4").unwrap();
        let new_version = bump_semver(BumpLevel::Rc, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.0.8-rc.1");

        let version = semver::Version::parse("0.0.8-rc.4").unwrap();
        let new_version = bump_semver(BumpLevel::Rc, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.0.8-rc.5");

        let version = semver::Version::parse("0.1.0-pre").unwrap();
        let new_version = bump_semver(BumpLevel::Rc, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.0-rc.1");

        let version = semver::Version::parse("0.1.1-pre.2").unwrap();
        let new_version = bump_semver(BumpLevel::Rc, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.1-rc.1");

        let version = semver::Version::parse("0.1.1").unwrap();
        let new_version = bump_semver(BumpLevel::Rc, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.1-rc.1");

        let version = semver::Version::parse("1.1.1-pre.1").unwrap();
        let new_version = bump_semver(BumpLevel::Rc, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.1.1-rc.1");

        let version = semver::Version::parse("1.1.1").unwrap();
        let new_version = bump_semver(BumpLevel::Rc, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.1.1-rc.1");

        let version = semver::Version::parse("1.0.0-rc.1").unwrap();
        let new_version = bump_semver(BumpLevel::Rc, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.0.0-rc.2");
    }

    #[test]
    fn bumps_pre_version_correctly() {
        let version = semver::Version::parse("0.0.8").unwrap();
        let new_version = bump_semver(BumpLevel::Pre, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.0.8-pre.1");

        let version = semver::Version::parse("0.0.8-pre.4").unwrap();
        let new_version = bump_semver(BumpLevel::Pre, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.0.8-pre.5");

        let version = semver::Version::parse("0.0.8-rc.4").unwrap();
        let new_version = bump_semver(BumpLevel::Pre, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.0.8-pre.1");

        let version = semver::Version::parse("0.1.0-pre").unwrap();
        let new_version = bump_semver(BumpLevel::Pre, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.0-pre.2");

        let version = semver::Version::parse("0.1.1-pre.2").unwrap();
        let new_version = bump_semver(BumpLevel::Pre, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.1-pre.3");

        let version = semver::Version::parse("0.1.1").unwrap();
        let new_version = bump_semver(BumpLevel::Pre, &version).unwrap();
        assert_eq!(new_version.to_string(), "0.1.1-pre.1");

        let version = semver::Version::parse("1.1.1-pre.1").unwrap();
        let new_version = bump_semver(BumpLevel::Pre, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.1.1-pre.2");

        let version = semver::Version::parse("1.1.1").unwrap();
        let new_version = bump_semver(BumpLevel::Pre, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.1.1-pre.1");

        let version = semver::Version::parse("1.0.0-rc.1").unwrap();
        let new_version = bump_semver(BumpLevel::Pre, &version).unwrap();
        assert_eq!(new_version.to_string(), "1.0.0-pre.1");
    }
}
