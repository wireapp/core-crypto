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
#[clap(name = "mls-test-cli")]
struct Cli {
    #[clap(short, long)]
    store: String,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init {
        client_id: ClientId,
    },
    KeyPackage {
        #[clap(subcommand)]
        command: KeyPackageCommand,
    },
    PublicKey,
    Group {
        #[clap(subcommand)]
        command: GroupCommand,
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
enum KeyPackageCommand {
    /// Create a new key package and save it in the store.
    Create,
    /// Compute the hash of a key package.
    Ref { key_package: String },
}

#[derive(Subcommand, Debug)]
enum GroupCommand {
    Create {
        group_id: String,
    },
    FromWelcome {
        welcome: String,
        #[clap(long)]
        group_out: String,
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

fn get_credential_bundle(backend: &impl OpenMlsCryptoProvider) -> CredentialBundle {
    let ks = backend.key_store();
    match ks.read(b"self") {
        Some(bundle) => bundle,
        None => {
            panic!("Credential not initialised. Please run `init` first.");
        }
    }
}

fn new_key_package(backend: &impl OpenMlsCryptoProvider) -> KeyPackageBundle {
    let cred_bundle = get_credential_bundle(backend);
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
        Command::Init { client_id } => {
            let ks = backend.key_store();
            match ks.read::<CredentialBundle>(b"self") {
                Some(_) => {
                    panic!("Credential already initialised");
                }
                None => {
                    let bundle =
                        CredentialBundle::new(client_id.0, CredentialType::Basic, SignatureScheme::ED25519, &backend)
                            .unwrap();
                    ks.store(b"self", &bundle).unwrap();
                    // also save credential under its signature key, as openmls assumes it is
                    // located there
                    ks.store(
                        &bundle.credential().signature_key().tls_serialize_detached().unwrap(),
                        &bundle,
                    )
                    .unwrap();
                }
            }
        }
        Command::KeyPackage {
            command: KeyPackageCommand::Create,
        } => {
            let key_package_bundle = new_key_package(&backend);

            // output key package to standard output
            key_package_bundle
                .key_package()
                .tls_serialize(&mut io::stdout())
                .unwrap();
        }
        Command::KeyPackage {
            command: KeyPackageCommand::Ref { key_package },
        } => {
            let mut kp_data = path_reader(&key_package).unwrap();
            let kp = KeyPackage::tls_deserialize(&mut kp_data).unwrap();
            io::stdout()
                .write_all(kp.hash_ref(backend.crypto()).unwrap().value())
                .unwrap();
        }
        Command::PublicKey => {
            let cred_bundle = get_credential_bundle(&backend);
            let credential = cred_bundle.credential();
            let bytes = credential.signature_key().as_slice();
            io::stdout().write_all(bytes).unwrap();
        }
        Command::Group {
            command: GroupCommand::Create { group_id },
        } => {
            let group_id = base64::decode(group_id).expect("Failed to decode group_id as base64");
            let group_id = GroupId::from_slice(&group_id);
            let group_config = default_configuration();

            let kp_bundle = new_key_package(&backend);
            let kp = kp_bundle.key_package();
            let kp_ref = kp.hash_ref(backend.crypto()).unwrap();
            let kp_hash = kp_ref.value();

            let mut group = MlsGroup::new(&backend, &group_config, group_id, kp_hash.as_slice()).unwrap();
            group.save(&mut io::stdout()).unwrap();
        }
        Command::Group {
            command: GroupCommand::FromWelcome { welcome, group_out },
        } => {
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
