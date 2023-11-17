use color_eyre::{eyre::ensure, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::process::Stdio;
use tokio::process::Command;
use tokio_stream::StreamExt;

pub fn store_path() -> String {
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    let name: String = (0usize..12)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();

    let mut cwd = std::env::current_dir().unwrap();
    cwd.push(format!("test.{name}.edb"));
    cwd.into_os_string().into_string().unwrap()
}

async fn run_init_with_bin(bin_name: &str, store_name: &str) -> Result<()> {
    let mut cwd = std::env::current_dir()?;
    cwd.push(bin_name);

    let output = Command::new("cargo")
        .current_dir(&cwd)
        .args(&["run", "--", store_name])
        .output()
        .await?;

    ensure!(
        output.status.success(),
        "Failed step with {bin_name} ❌\n\n{}",
        String::from_utf8(output.stderr)?
    );
    Ok(())
}

async fn warmup_build() -> Result<()> {
    let spinner = init_spinner();
    spinner.set_prefix("cargo: ");

    let cwd = std::env::current_dir()?;
    let bins = [
        "cc-keystore-08",
        "cc-keystore-09",
        "cc-keystore-10p",
        "cc-keystore-10r",
        "cc-keystore-current",
    ];
    for bin in bins {
        let mut cargo_cmd = Command::new("cargo")
            .current_dir(&cwd.join(bin))
            .args(&["build"])
            .stderr(Stdio::piped())
            .spawn()?;

        let mut stderr = tokio_stream::wrappers::LinesStream::new(
            tokio::io::BufReader::new(cargo_cmd.stderr.take().unwrap()).lines(),
        );
        use tokio::io::AsyncBufReadExt as _;
        while let Some(line) = stderr.next().await {
            let line = line?;
            let stripped = line.trim();
            if !stripped.is_empty() {
                spinner.set_message(stripped.to_owned());
            }
            spinner.tick();
        }

        cargo_cmd.wait().await?;
    }

    spinner.finish_with_message("build warmup ✅");

    Ok(())
}

fn init_spinner() -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(std::time::Duration::from_millis(120));
    spinner.set_style(ProgressStyle::with_template("{spinner:.dim.bold} {prefix}{wide_msg}").unwrap());
    spinner
}

fn spinner_wrap_err<T>(spinner: &ProgressBar, result: Result<T>) -> Result<T> {
    if let Err(e) = &result {
        spinner.abandon_with_message(format!("{e} ❌"));
    }
    result
}

#[tokio::main]
async fn main() -> Result<()> {
    warmup_build().await?;

    let ks_10p = store_path();
    let ks_10r = store_path();
    let ks_08 = store_path();

    let spinner_10p = init_spinner();

    // === Android ===

    // Initialize a Keystore on version 0.8.2, let this keystore as ks-08
    spinner_wrap_err(&spinner_10p, run_init_with_bin("cc-keystore-08", &ks_10p).await)?;
    spinner_10p.set_message("0.8.2");
    // Try to open and migrate ks-08 to version 1.0.0-pre, let this keystore as ks-10p
    spinner_wrap_err(&spinner_10p, run_init_with_bin("cc-keystore-10p", &ks_10p).await)?;
    spinner_10p.set_message("0.8.2 -> 1.0.0-pre");

    // Try to open and migrate ks-10p to version 1.0.0-rc, let this keystore as ks-10pr
    spinner_wrap_err(&spinner_10p, run_init_with_bin("cc-keystore-10r", &ks_10p).await)?;
    spinner_10p.set_message("0.8.2 -> 1.0.0-pre -> 1.0.0-rc");

    spinner_wrap_err(&spinner_10p, run_init_with_bin("cc-keystore-current", &ks_10p).await)?;
    spinner_10p.finish_with_message("0.8.2 -> 1.0.0-pre -> 1.0.0-rc -> develop ✅");
    tokio::fs::remove_file(&ks_10p).await?;

    let spinner_10r = init_spinner();

    // Try to open and migrate ks-08 to version 1.0.0-rc, let this keystore as ks-10r
    spinner_wrap_err(&spinner_10r, run_init_with_bin("cc-keystore-08", &ks_10r).await)?;
    spinner_10r.set_message("0.8.2");

    spinner_wrap_err(&spinner_10r, run_init_with_bin("cc-keystore-10r", &ks_10r).await)?;
    spinner_10r.set_message("0.8.2 -> 1.0.0-rc");

    spinner_wrap_err(&spinner_10r, run_init_with_bin("cc-keystore-current", &ks_10r).await)?;
    tokio::fs::remove_file(&ks_10r).await?;

    spinner_10r.finish_with_message("0.8.2 -> 1.0.0-rc -> develop ✅");

    let spinner_current = init_spinner();

    // Try to open and migrate a ks08 directly to current version
    spinner_wrap_err(&spinner_current, run_init_with_bin("cc-keystore-08", &ks_08).await)?;
    spinner_current.set_message("0.8.2");

    spinner_wrap_err(&spinner_current, run_init_with_bin("cc-keystore-current", &ks_08).await)?;
    tokio::fs::remove_file(&ks_08).await?;
    spinner_current.finish_with_message("0.8.2 -> develop ✅");

    // === iOS ===

    // Initialize a Keystore on version 0.8.2, let this keystore as ks-09
    spinner_wrap_err(&spinner_10p, run_init_with_bin("cc-keystore-09", &ks_10p).await)?;
    spinner_10p.set_message("0.9.2");
    // Try to open and migrate ks-09 to version 1.0.0-pre, let this keystore as ks-10p
    spinner_wrap_err(&spinner_10p, run_init_with_bin("cc-keystore-10p", &ks_10p).await)?;
    spinner_10p.set_message("0.9.2 -> 1.0.0-pre");

    // Try to open and migrate ks-10p to version 1.0.0-rc, let this keystore as ks-10pr
    spinner_wrap_err(&spinner_10p, run_init_with_bin("cc-keystore-10r", &ks_10p).await)?;
    spinner_10p.set_message("0.9.2 -> 1.0.0-pre -> 1.0.0-rc");

    spinner_wrap_err(&spinner_10p, run_init_with_bin("cc-keystore-current", &ks_10p).await)?;
    spinner_10p.finish_with_message("0.9.2 -> 1.0.0-pre -> 1.0.0-rc -> develop ✅");
    tokio::fs::remove_file(&ks_10p).await?;

    let spinner_10r = init_spinner();

    // Try to open and migrate ks-08 to version 1.0.0-rc, let this keystore as ks-10r
    spinner_wrap_err(&spinner_10r, run_init_with_bin("cc-keystore-09", &ks_10r).await)?;
    spinner_10r.set_message("0.9.2");

    spinner_wrap_err(&spinner_10r, run_init_with_bin("cc-keystore-10r", &ks_10r).await)?;
    spinner_10r.set_message("0.9.2 -> 1.0.0-rc");

    spinner_wrap_err(&spinner_10r, run_init_with_bin("cc-keystore-current", &ks_10r).await)?;
    tokio::fs::remove_file(&ks_10r).await?;

    spinner_10r.finish_with_message("0.9.2 -> 1.0.0-rc -> develop ✅");

    let spinner_current = init_spinner();

    // Try to open and migrate a ks08 directly to current version
    spinner_wrap_err(&spinner_current, run_init_with_bin("cc-keystore-09", &ks_08).await)?;
    spinner_current.set_message("0.9.2");

    spinner_wrap_err(&spinner_current, run_init_with_bin("cc-keystore-current", &ks_08).await)?;
    tokio::fs::remove_file(&ks_08).await?;
    spinner_current.finish_with_message("0.9.2 -> develop ✅");

    Ok(())
}
