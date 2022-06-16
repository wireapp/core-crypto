use core_crypto::prelude::*;
use mls_crypto_provider::*;
use openmls::prelude::*;

use clap::{Parser, Subcommand};
use io::Read;
use io::Write;
use std::fs;
use std::io;

#[derive(Parser, Debug)]
#[clap(name = "crypto-cli")]
struct Cli {
    /// Sqlcipher backing file
    #[clap(short, long)]
    store: String,
    /// Sqlcipher passphrase
    #[clap(short, long)]
    enc_key: String,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a new keypackage for existing or new client
    KeyPackage { client_id: ClientId },
    /// Generate a hash of a key package
    KeyPackageRef { key_package: String },
    /// Get existing or new client signature key
    PublicKey { client_id: ClientId },
    /// Create a new MLS group
    Group {
        client_id: ClientId,
        group_id: String,
        key_package_ref_out: Option<String>,
    },
    /// Create a group from a welcome message
    GroupFromWelcome { welcome: String, group_out: String },
    Member {
        /// Existing group id
        #[clap(short, long)]
        group: String,
        #[clap(subcommand)]
        command: MemberCommand,
    },
    Proposal {
        /// The ID of the client creating the proposal
        client_id: ClientId,
        /// Existing group id
        #[clap(short, long)]
        group_id: String,
        /// The output file
        #[clap(long)]
        proposal_out: Option<String>,
        #[clap(subcommand)]
        command: ProposalCommand,
    },
    /// Send a message in an MLS group
    Message {
        /// Existing group id
        #[clap(short, long)]
        group: String,
        /// Message to send
        text: String,
    },
}

#[derive(Subcommand, Debug)]
enum MemberCommand {
    /// Add a new member to an existing group
    Add {
        /// New member TLS serialized KeyPackage
        key_packages: Vec<String>,
        /// Output for Welcome message
        #[clap(short, long)]
        welcome_out: Option<String>,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ProposalCommand {
    /// Create an add proposal
    Add { key_package_in: String },
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
        Command::GroupFromWelcome { welcome, group_out } => {
            let group_config = MlsConversationConfiguration::openmls_default_configuration();
            let welcome = Welcome::tls_deserialize(&mut fs::File::open(welcome).unwrap()).unwrap();
            let mut group = MlsGroup::new_from_welcome(&backend, &group_config, welcome, None).unwrap();
            let mut group_out = fs::File::create(group_out).unwrap();
            group.save(&mut group_out).unwrap();
        }
        Command::Member {
            group: group_in,
            command:
                MemberCommand::Add {
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
        Command::Proposal {
            client_id,
            group_id,
            proposal_out,
            command: ProposalCommand::Add { key_package_in },
        } => {
            let key_package = {
                let mut data = path_reader(&key_package_in).unwrap();
                KeyPackage::tls_deserialize(&mut data).unwrap()
            };
            let central = MlsCentral::try_new(
                MlsCentralConfiguration::try_new(cli.store, cli.enc_key, client_id.to_string()).unwrap(),
            )
            .unwrap();
            let prop = central
                .new_proposal(group_id.as_bytes().to_vec(), MlsProposal::Add(key_package))
                .unwrap()
                .to_bytes()
                .unwrap();
            if let Some(proposal_out) = proposal_out {
                fs::File::create(proposal_out).unwrap().write(&prop).unwrap();
            } else {
                io::stdout().write(&prop).unwrap();
            }
        }
        Command::Message { group, text } => {
            let mut group_data = path_reader(&group).unwrap();
            app_message(&backend, &mut group_data, text);
        }
    }
}

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

fn group(backend: &MlsCryptoProvider, client_id: ClientId, group_id: &[u8]) {
    let client = Client::init(client_id, &backend).unwrap();
    let group_id = GroupId::from_slice(group_id);
    let group_config = MlsConversationConfiguration::openmls_default_configuration();
    let kp_hash = client.keypackage_hash(&backend).unwrap();
    let mut group = MlsGroup::new(backend, &group_config, group_id, kp_hash.as_slice()).unwrap();
    group.save(&mut io::stdout()).unwrap();
}

fn add_member<W: Write>(
    backend: &MlsCryptoProvider,
    group_data: &mut dyn Read,
    mut kp_data: &mut dyn Read,
    opt_wel_data: Option<W>,
) {
    let mut group = MlsGroup::load(group_data).unwrap();
    let kp = KeyPackage::tls_deserialize(&mut kp_data).unwrap();
    let (handshake, welcome) = group.add_members(backend, &[kp]).unwrap();
    handshake.tls_serialize(&mut io::stdout()).unwrap();
    if let Some(mut wel_data) = opt_wel_data {
        welcome.tls_serialize(&mut wel_data).unwrap();
    }
}

fn app_message(backend: &MlsCryptoProvider, group_data: &mut dyn Read, text: String) {
    let mut group = MlsGroup::load(group_data).unwrap();
    let message = group.create_message(backend, text.as_bytes()).unwrap();
    message.tls_serialize(&mut io::stdout()).unwrap();
}
