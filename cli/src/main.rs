use openmls::{
    ciphersuite::{ciphersuites::CiphersuiteName, Ciphersuite},
    credentials::{CredentialBundle, CredentialType},
    key_packages::KeyPackageBundle,
};
use openmls_rust_crypto::{OpenMlsRustCrypto};
use openmls::prelude::{TlsSerializeTrait};
use core_crypto::prelude::ClientId;

use clap::{Parser, Subcommand};
use std::io::Write;

fn key_package(client_id: &ClientId) {
    let backend = OpenMlsRustCrypto::default();
    let ciphersuite_name = CiphersuiteName::default();
    let ciphersuite = Ciphersuite::new(ciphersuite_name).unwrap();

    let credentials = CredentialBundle::new(
        client_id.as_bytes(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        &backend,
    ).unwrap();

    let kps = KeyPackageBundle::new(
        &[ciphersuite_name],
        &credentials,
        &backend,
        vec![]
    ).unwrap();

    let kp = kps.key_package();
    let mut kp_bytes = Vec::new();
    kp.tls_serialize(&mut kp_bytes).unwrap();
    std::io::stdout().write_all(&kp_bytes).unwrap();
}


#[derive(Parser)]
#[derive(Debug)]
#[clap(name = "crypto-cli")]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[derive(Debug)]
enum Command {
    KeyPackage {
        client_id: ClientId
    },
}

fn execute(cmd: &Command) {
    match cmd {
        Command::KeyPackage { client_id } => key_package(client_id),
    }
}

fn main() {
    let cli = Cli::parse();
    execute(&cli.command);
}
