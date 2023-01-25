use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;

mod documentation;
mod release;

use crate::documentation::DocumentationCommands;
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
    Documentation(DocumentationCommands),
    #[clap(subcommand)]
    Release(ReleaseCommands),
}

fn main() -> Result<()> {
    color_eyre::install()?;
    femme::start();

    let cli = Xtask::parse();

    match cli.command {
        Commands::Documentation(doc_command) => match doc_command {
            DocumentationCommands::Build { .. } => documentation::build()?,
            DocumentationCommands::Changelog { dry_run } => documentation::changelog(dry_run)?,
        },
        Commands::Release(release_command) => match release_command {
            ReleaseCommands::Bump { version, dry_run } => release::bump(version, dry_run)?,
        },
    }

    Ok(())
}
