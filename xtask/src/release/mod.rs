mod bump;
pub use bump::*;

#[derive(Debug, clap::Subcommand)]
pub enum ReleaseCommands {
    Bump {
        #[clap(value_parser)]
        version: bump::BumpLevel,
        #[clap(long, action)]
        dry_run: bool,
    },
}
