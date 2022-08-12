use color_eyre::eyre::{eyre, Result};
use handlebars::{Context, Handlebars, Helper, Output, RenderContext};
use xshell::{cmd, Shell};

pub fn changelog(dry_run: bool) -> Result<()> {
    let mut handlebars = Handlebars::new();
    let sh = Shell::new()?;
    let repo = git2::Repository::open(".")?;
    let mut refs = serde_json::Map::new();

    let head_ref = repo
        .head()?
        .target()
        .ok_or_else(|| eyre!("HEAD is not pointing at a valid ref. Detached state detected, we bail!"))?
        .to_string();

    log::debug!("Found git HEAD at {head_ref}");

    let tail_ref = cmd!(sh, "git rev-list --max-parents=0 HEAD").read()?;

    log::debug!("Found git TAIL at {tail_ref}");

    let mut prev_ref = tail_ref;

    for ref_result in repo.references()? {
        let git_ref = ref_result?;

        let ref_name = git_ref.name().ok_or_else(|| eyre!("Ref name is not valid utf-8!"))?;

        if !git_ref.is_tag() {
            continue;
        }

        let ref_target = git_ref
            .target()
            .ok_or_else(|| eyre!("Ref target {ref_name} isn't valid!"))?;

        let normalized_ref_name = git2::Reference::normalize_name(
            &ref_name.replace("refs/tags/", ""),
            git2::ReferenceFormat::ALLOW_ONELEVEL | git2::ReferenceFormat::REFSPEC_SHORTHAND,
        )?;

        let tag_range = format!("{prev_ref}..{ref_target}");

        log::debug!("Found git range for tag {normalized_ref_name}: {tag_range}");

        refs.insert(normalized_ref_name, tag_range.into());
        prev_ref = ref_target.to_string();
    }

    handlebars.register_template_file("changelog", "CHANGELOG.tpl")?;
    handlebars.register_helper(
        "git-cliff",
        Box::new(
            |h: &Helper, _r: &Handlebars, ctx: &Context, _rc: &mut RenderContext, out: &mut dyn Output| {
                let refs = &ctx.data().as_object().unwrap()["refs"];
                let git_tag = h.hash_get("tag").and_then(|tag| tag.value().as_str()).unwrap();
                let unreleased = h
                    .hash_get("unreleased")
                    .and_then(|unr| unr.value().as_bool())
                    .unwrap_or_default();

                let local_sh = Shell::new().unwrap();

                let output = if unreleased {
                    cmd!(local_sh, "git cliff --tag {git_tag} -ul").read().unwrap()
                } else {
                    let targeted_ref_range = refs.get(git_tag).unwrap().as_str().unwrap();
                    cmd!(local_sh, "git cliff {targeted_ref_range}").read().unwrap()
                };

                out.write(&output)?;
                Ok(())
            },
        ),
    );

    let mut data = serde_json::Map::default();
    data.insert("refs".into(), refs.into());
    data.insert("head_ref".into(), head_ref.into());
    let output = handlebars.render("changelog", &data)?;
    if dry_run {
        log::info!("Changelog generated successfully");
        log::info!("Dry run selected, just printing");
        println!("{output}");
        return Ok(());
    }

    std::fs::write("CHANGELOG.md", output)?;

    log::info!("Changelog written to CHANGELOG.md");

    Ok(())
}
