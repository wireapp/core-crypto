use core_crypto::prelude::*;
use mls_crypto_provider::*;
use openmls::prelude::*;

use clap::{Parser, Subcommand};
use io::Read;
use io::Write;
use std::fs;
use std::io;
use std::str::FromStr;

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
    KeyPackage { client_id: String },
    /// Get existing or new client signature key
    PublicKey { client_id: String },
    /// Create a new MLS group
    Group { client_id: String, group_id: String },
    /// Update an existing MLS group
    Member {
        /// Existing group id
        #[clap(short, long)]
        group: String,
        #[clap(subcommand)]
        command: MemberCommand,
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
        key_package: String,
        /// Output for Welcome message
        #[clap(short, long)]
        welcome_out: Option<String>,
    },
}

fn path_reader(path: String) -> io::Result<Box<dyn Read>> {
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
        Command::KeyPackage { client_id } => key_package(&backend, ClientId::from_str(&client_id).unwrap()),
        Command::PublicKey { client_id } => public_key(&backend, ClientId::from_str(&client_id).unwrap()),
        Command::Group { client_id, group_id } => group(&backend, ClientId::from_str(&client_id).unwrap(), group_id.as_bytes()),
        Command::Member {
            group,
            command: MemberCommand::Add {
                key_package,
                welcome_out,
            },
        } => {
            let mut group_data = path_reader(group).unwrap();
            let mut kp_data = path_reader(key_package).unwrap();
            let wel_data = welcome_out.map(|path| fs::File::create(path).unwrap());
            add_member(&backend, &mut group_data, &mut kp_data, wel_data);
        }
        Command::Message { group, text } => {
            let mut group_data = path_reader(group).unwrap();
            app_message(&backend, &mut group_data, text);
        }
    }
}

fn key_package(backend: &MlsCryptoProvider, client_id: ClientId) {
    let client = Client::init(client_id, None, &backend).unwrap();
    let kpb = client.gen_keypackage(&backend).unwrap();
    kpb.key_package().tls_serialize(&mut io::stdout()).unwrap();
}

fn public_key(backend: &MlsCryptoProvider, client_id: ClientId) {
    let client = Client::init(client_id, None, &backend).unwrap();
    let pk = client.public_key();
    io::stdout().write_all(pk).unwrap();
}

fn group(backend: &MlsCryptoProvider, client_id: ClientId, group_id: &[u8]) {
    let client = Client::init(client_id, None, &backend).unwrap();
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
