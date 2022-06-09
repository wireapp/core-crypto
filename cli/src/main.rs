use core_crypto::prelude::*;
use mls_crypto_provider::*;
use openmls::prelude::*;

use clap::{Parser, Subcommand};
use io::Read;
use io::Write;
use std::fs;
use std::io;

fn key_package(backend: &MlsCryptoProvider, client_id: ClientId) {
    let client = Client::init(client_id, &backend).unwrap();
    let kpb = client.gen_keypackage(&backend).unwrap();
    kpb.key_package().tls_serialize(&mut io::stdout()).unwrap();
}

fn public_key(backend: &MlsCryptoProvider, client_id: ClientId) {
    let client = Client::init(client_id, &backend).unwrap();
    let pk = client.public_key();
    io::stdout().write_all(pk).unwrap();
}

fn app_message(backend: &MlsCryptoProvider, group_data: &mut dyn Read, text: String) {
    let mut group = MlsGroup::load(group_data).unwrap();
    let message = group.create_message(backend, text.as_bytes()).unwrap();
    message.tls_serialize(&mut io::stdout()).unwrap();
}

#[derive(Parser, Debug)]
#[clap(name = "crypto-cli")]
struct Cli {
    #[clap(short, long)]
    store: String,
    #[clap(short, long)]
    enc_key: String,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    KeyPackage {
        client_id: ClientId,
    },
    KeyPackageRef {
        key_package: String,
    },
    PublicKey {
        client_id: ClientId,
    },
    Group {
        client_id: ClientId,
        group_id: String,
        /// A file where to store the key package used by the creator of the group.
        #[clap(long)]
        key_package_ref_out: Option<String>,
    },
    Member {
        #[clap(subcommand)]
        command: MemberCommand,
    },
    Message {
        #[clap(short, long)]
        group: String,
        text: String,
    },
}

#[derive(Subcommand, Debug)]
enum MemberCommand {
    Add {
        #[clap(short, long)]
        group: String,
        key_packages: Vec<String>,
        #[clap(short, long)]
        welcome_out: Option<String>,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
    },
}

fn path_reader(path: &str) -> io::Result<Box<dyn Read>> {
    if path == "-" {
        Ok(Box::new(io::stdin()))
    } else {
        Ok(Box::new(fs::File::open(path)?))
    }
}

fn main() {
    let cli = Cli::parse();
    let backend = MlsCryptoProvider::try_new(&cli.store, &cli.enc_key).unwrap();
    match cli.command {
        Command::KeyPackage { client_id } => key_package(&backend, client_id),
        Command::KeyPackageRef { key_package } => {
            let mut kp_data = path_reader(&key_package).unwrap();
            let kp = KeyPackage::tls_deserialize(&mut kp_data).unwrap();
            io::stdout()
                .write_all(kp.hash_ref(backend.crypto()).unwrap().value())
                .unwrap();
        }
        Command::PublicKey { client_id } => public_key(&backend, client_id),
        Command::Group {
            client_id,
            group_id,
            key_package_ref_out,
        } => {
            let group_id = base64::decode(group_id).expect("Failed to decode group_id as base64");
            let group_id = GroupId::from_slice(&group_id);
            let client = Client::init(client_id, &backend).unwrap();
            let group_config = MlsConversationConfiguration::openmls_default_configuration();
            let kp_hash = client.keypackage_hash(&backend).unwrap();
            if let Some(key_package_ref_out) = key_package_ref_out {
                let mut file = fs::File::create(key_package_ref_out).unwrap();
                file.write(kp_hash.value()).unwrap();
            }
            let mut group = MlsGroup::new(&backend, &group_config, group_id, kp_hash.as_slice()).unwrap();
            group.save(&mut io::stdout()).unwrap();
        }
        Command::Member {
            command:
                MemberCommand::Add {
                    group: group_in,
                    key_packages,
                    welcome_out,
                    group_out,
                    in_place,
                },
        } => {
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                MlsGroup::load(data).unwrap()
            };
            let kps = key_packages
                .into_iter()
                .map(|kp| {
                    let mut data = path_reader(&kp).expect(&format!("Could not open key package file: {}", kp));
                    KeyPackage::tls_deserialize(&mut data).unwrap()
                })
                .collect::<Vec<_>>();
            let (handshake, welcome) = group.add_members(&backend, &kps).unwrap();

            if let Some(welcome_out) = welcome_out {
                let mut writer = fs::File::create(welcome_out).unwrap();
                welcome.tls_serialize(&mut writer).unwrap();
            }
            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                group.merge_pending_commit().unwrap();
                group.save(&mut writer).unwrap();
            }
            handshake.tls_serialize(&mut io::stdout()).unwrap();
        }
        Command::Message { group, text } => {
            let mut group_data = path_reader(&group).unwrap();
            app_message(&backend, &mut group_data, text);
        }
    }
}
