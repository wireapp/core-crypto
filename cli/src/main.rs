use openmls::prelude::{TlsSerializeTrait};
use core_crypto::prelude::*;
use mls_crypto_provider::*;

use clap::{Parser, Subcommand};
use std::io::Write;

fn key_package(backend: &MlsCryptoProvider, client_id: ClientId) {
    let mut client = Client::init(client_id, &backend).unwrap();
    let kp = client.gen_keypackage(&backend).unwrap();
    let mut kp_bytes = Vec::new();
    kp.tls_serialize(&mut kp_bytes).unwrap();
    std::io::stdout().write_all(&kp_bytes).unwrap();
}

fn public_key(backend: &MlsCryptoProvider, client_id: ClientId) {
    let client = Client::init(client_id, &backend).unwrap();
    let pk = client.public_key();
    std::io::stdout().write_all(pk).unwrap();
}

#[derive(Parser)]
#[derive(Debug)]
#[clap(name = "crypto-cli")]
struct Cli {
    #[clap(short, long)]
    store: String,
    #[clap(short, long)]
    enc_key: String,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[derive(Debug)]
enum Command {
    KeyPackage {
        client_id: ClientId
    },
    PublicKey {
        client_id: ClientId
    },
}


fn main() {
    let cli = Cli::parse();
    let backend = MlsCryptoProvider::try_new(&cli.store, &cli.enc_key).unwrap();
    match cli.command {
        Command::KeyPackage { client_id } => key_package(&backend, client_id),
        Command::PublicKey { client_id } => public_key(&backend, client_id),
    }
}
