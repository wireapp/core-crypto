use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;

mod documentation;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Xtask {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[clap(subcommand)]
    Documentation(DocumentationCommands),
}

#[derive(Debug, Subcommand)]
enum DocumentationCommands {
    Build {
        // TODO: Add platforms to build documentation for
        #[clap(value_parser)]
        platforms: Option<String>,
    },
    Changelog {
        #[clap(long, action)]
        dry_run: bool,
    },
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Xtask::parse();

    match cli.command {
        Commands::Documentation(doc_command) => match &doc_command {
            DocumentationCommands::Build { .. } => documentation::build()?,
            DocumentationCommands::Changelog { dry_run } => documentation::changelog(*dry_run)?,
        },
    }

    Ok(())
}
