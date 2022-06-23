mod backend;
mod keystore;

use openmls::prelude::*;

use backend::TestBackend;

use clap::{Parser, Subcommand};
use io::Read;
use io::Write;
use std::fs;
use std::io;

#[derive(Debug)]
struct ClientId(Vec<u8>);

impl core::str::FromStr for ClientId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Ok(ClientId(s.as_bytes().to_vec()))
    }
}

#[derive(Parser, Debug)]
#[clap(name = "crypto-cli")]
struct Cli {
    #[clap(short, long)]
    store: String,
    #[clap(short, long)]
    _enc_key: Option<String>,
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
    },
    GroupFromWelcome {
        welcome: String,
        #[clap(long)]
        group_out: String,
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

fn default_configuration() -> MlsGroupConfig {
    MlsGroupConfig::builder()
        .wire_format_policy(openmls::group::MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(3)
        .padding_size(16)
        .number_of_resumtion_secrets(1)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(2, 5))
        .use_ratchet_tree_extension(true)
        .build()
}

fn get_credential_bundle(backend: &impl OpenMlsCryptoProvider, client_id: ClientId) -> CredentialBundle {
    let ks = backend.key_store();
    match ks.read(b"self") {
        Some(bundle) => {
            // TODO: check that the client id matches
            bundle
        }
        None => {
            let bundle =
                CredentialBundle::new(client_id.0, CredentialType::Basic, SignatureScheme::ED25519, backend).unwrap();
            ks.store(b"self", &bundle).unwrap();
            bundle
        }
    }
}

fn new_key_package(backend: &impl OpenMlsCryptoProvider, client_id: ClientId) -> KeyPackageBundle {
    let cred_bundle = get_credential_bundle(backend, client_id);
    let extensions = vec![];
    let ciphersuites = [Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519];
    let kp_bundle = KeyPackageBundle::new(&ciphersuites, &cred_bundle, backend, extensions).unwrap();

    // store the key package bundle in the key store
    let key_package = kp_bundle.key_package();
    backend
        .key_store()
        .store(key_package.hash_ref(backend.crypto()).unwrap().value(), &kp_bundle)
        .unwrap();

    kp_bundle
}

fn main() {
    let cli = Cli::parse();
    let backend = TestBackend::new(&cli.store).unwrap();
    match cli.command {
        Command::KeyPackage { client_id } => {
            let key_package_bundle = new_key_package(&backend, client_id);

            // output key package to standard output
            key_package_bundle
                .key_package()
                .tls_serialize(&mut io::stdout())
                .unwrap();
        }
        Command::KeyPackageRef { key_package } => {
            let mut kp_data = path_reader(&key_package).unwrap();
            let kp = KeyPackage::tls_deserialize(&mut kp_data).unwrap();
            io::stdout()
                .write_all(kp.hash_ref(backend.crypto()).unwrap().value())
                .unwrap();
        }
        Command::PublicKey { client_id } => {
            let cred_bundle = get_credential_bundle(&backend, client_id);
            let credential = cred_bundle.credential();
            let bytes = credential.signature_key().as_slice();
            io::stdout().write_all(bytes).unwrap();
        }
        Command::Group { client_id, group_id } => {
            let group_id = base64::decode(group_id).expect("Failed to decode group_id as base64");
            let group_id = GroupId::from_slice(&group_id);
            let group_config = default_configuration();

            let kp_bundle = new_key_package(&backend, client_id);
            let kp = kp_bundle.key_package();
            let kp_ref = kp.hash_ref(backend.crypto()).unwrap();
            let kp_hash = kp_ref.value();

            let mut group = MlsGroup::new(&backend, &group_config, group_id, kp_hash.as_slice()).unwrap();
            group.save(&mut io::stdout()).unwrap();
        }
        Command::GroupFromWelcome { welcome, group_out } => {
            let group_config = default_configuration();
            let welcome = Welcome::tls_deserialize(&mut fs::File::open(welcome).unwrap()).unwrap();
            let mut group = MlsGroup::new_from_welcome(&backend, &group_config, welcome, None).unwrap();
            let mut group_out = fs::File::create(group_out).unwrap();
            group.save(&mut group_out).unwrap();
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
            let group_data = path_reader(&group).unwrap();
            let mut group = MlsGroup::load(group_data).unwrap();
            let message = group.create_message(&backend, text.as_bytes()).unwrap();
            message.tls_serialize(&mut io::stdout()).unwrap();
        }
    }
}
