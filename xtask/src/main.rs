use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;

mod release;

use crate::release::ReleaseCommands;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Xtask {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[clap(subcommand)]
    Release(ReleaseCommands),
}

fn main() -> Result<()> {
    color_eyre::install()?;
    femme::start();

    let cli = Xtask::parse();

    match cli.command {
        Commands::Release(release_command) => match release_command {
            ReleaseCommands::Bump { version, dry_run } => release::bump(version, dry_run)?,
        },
    }

    Ok(())
}
