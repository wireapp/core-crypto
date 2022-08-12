use color_eyre::eyre::{eyre, Result};
use std::path::Path;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
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

pub fn bump(bump_version: BumpLevel, dry_run: bool) -> Result<()> {
    let cargo_config = cargo::util::Config::default().map_err(|e| eyre!(e.to_string()))?;
    let ws = cargo::core::Workspace::new(&Path::new("./Cargo.toml").canonicalize()?, &cargo_config)
        .map_err(|e| eyre!(e.to_string()))?;

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

        log::info!("Found workspace member {package_name}@{semver_version}");

        let new_semver_version = bump_semver(bump_version, &semver_version)?;
        log::info!("Bumping {package_name}: {semver_version} -> {new_semver_version}");

        if !dry_run {
            manifest["package"]["version"] = toml_edit::value(new_semver_version.to_string());
            std::fs::write(manifest_path, manifest.to_string())?;
            log::debug!("Wrote new manifest");
        } else {
            log::info!("Dry run selected, doing nothing");
        }
    }

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
