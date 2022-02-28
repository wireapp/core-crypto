use openmls::prelude::*;
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

fn group(backend: &MlsCryptoProvider, client_id: ClientId, group_id: &[u8]) {
    let mut client = Client::init(client_id, &backend).unwrap();
    let group_id = GroupId::from_slice(group_id);
    let group_config = MlsConversationConfiguration::openmls_default_configuration();
    let kp_hash = client.keypackage_hash(&backend).unwrap();
    let mut group = MlsGroup::new(backend, &group_config, group_id, &kp_hash).unwrap();
    group.save(&mut std::io::stdout()).unwrap();
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
    Group {
        client_id: ClientId,
        group_id: Vec<u8>,
    }
}


fn main() {
    let cli = Cli::parse();
    let backend = MlsCryptoProvider::try_new(&cli.store, &cli.enc_key).unwrap();
    match cli.command {
        Command::KeyPackage { client_id } => key_package(&backend, client_id),
        Command::PublicKey { client_id } => public_key(&backend, client_id),
        Command::Group { client_id, group_id } => group(&backend, client_id, &group_id),
    }
}
