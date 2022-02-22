use openmls::prelude::{TlsSerializeTrait};
use core_crypto::prelude::*;
use mls_crypto_provider::*;

use clap::{Parser, Subcommand};
use std::io::Write;

fn key_package(path: &String, enc_key: &String, client_id: ClientId) {
    let backend = MlsCryptoProvider::try_new(path, enc_key).unwrap();
    let mut client = Client::init(client_id, &backend).unwrap();
    let kp = client.gen_keypackage(&backend).unwrap();
    let mut kp_bytes = Vec::new();
    kp.tls_serialize(&mut kp_bytes).unwrap();
    std::io::stdout().write_all(&kp_bytes).unwrap();
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
}


fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::KeyPackage { client_id } => key_package(&cli.store, &cli.enc_key, client_id),
    }
}
