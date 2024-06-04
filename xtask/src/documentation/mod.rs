mod build;
pub use build::build;
mod changelog;
pub use changelog::changelog;

#[derive(Debug, clap::Subcommand)]
pub enum DocumentationCommands {
    Build {
        #[clap(value_parser)]
        platforms: Option<String>,
    },
    Changelog {
        #[clap(long, action)]
        dry_run: bool,
    },
}
