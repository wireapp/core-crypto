#[cfg(not(target_os = "unknown"))]
use anyhow::{anyhow, bail};

#[cfg(target_os = "unknown")]
fn main() -> anyhow::Result<()> {
    println!("the keystore dump tool is not available for WASM");
    Ok(())
}

#[cfg(not(target_os = "unknown"))]
#[macro_rules_attribute::apply(smol_macros::main)]
async fn main() -> anyhow::Result<()> {
    #[derive(Debug, clap::Parser)]
    #[command(author, version, about, long_about = None)]
    struct Args {
        #[arg(short, long)]
        /// The 256-bit database key, hex-encoded.
        key: String,

        path: String,
    }

    use clap::Parser as _;
    use core_crypto_keystore::{Database as Keystore, DatabaseKey, entities::*, traits::FetchFromDatabase};
    use openmls::prelude::tls_codec::Deserialize as _;
    use serde::ser::{SerializeMap, Serializer};

    let args = Args::parse();

    if !std::path::Path::new(&args.path).exists() {
        bail!("File not found: {}", args.path);
    }

    let key = DatabaseKey::try_from(hex::decode(&args.key)?.as_slice())?;
    let keystore = Keystore::open(&args.path, &key)
        .await
        .map_err(|e| anyhow!("The passkey is probably wrong; [err: {e}]"))?;

    let mut json_serializer = serde_json::Serializer::pretty(std::io::stdout());
    let mut json_map = json_serializer.serialize_map(None)?;

    let mut credentials: Vec<serde_json::Value> = vec![];
    for cred in keystore.load_all::<StoredCredential>().await?.into_iter() {
        let mls_credential = openmls::prelude::Credential::tls_deserialize(&mut cred.credential.as_slice())?;
        let mls_keypair = openmls_basic_credential::SignatureKeyPair::from_raw(
            core_crypto::CipherSuite::try_from(cred.ciphersuite)
                .expect("ciphersuite from db")
                .signature_algorithm(),
            cred.private_key.to_owned(),
            cred.public_key.to_owned(),
        );
        let date = jiff::Timestamp::from_second(cred.created_at as i64)?;

        credentials.push(serde_json::json!({
            "session_id": cred.session_id,
            "credential": mls_credential,
            "created_at": date,
            "mls_keypair": mls_keypair,
            "private_key": cred.private_key,
            "public_key": cred.public_key,
        }));
    }
    json_map.serialize_entry("mls_credentials", &credentials)?;

    let hpke_sks: Vec<openmls_traits::types::HpkePrivateKey> = keystore
        .load_all::<StoredHpkePrivateKey>()
        .await?
        .into_iter()
        .map(|hpke_sk| postcard::from_bytes::<openmls_traits::types::HpkePrivateKey>(&hpke_sk.secret_key))
        .collect::<postcard::Result<_>>()?;
    json_map.serialize_entry("mls_hpke_private_keys", &hpke_sks)?;

    /// openmls's `EncryptionKeyPair`, which is private to it.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct EncryptionKeyPair {
        public_key: Vec<u8>,
        private_key: openmls_traits::types::HpkePrivateKey,
    }

    let hpke_keypairs: Vec<EncryptionKeyPair> = keystore
        .load_all::<StoredEncryptionKeyPair>()
        .await?
        .into_iter()
        .map(|hpke_kp| postcard::from_bytes::<EncryptionKeyPair>(&hpke_kp.sk))
        .collect::<postcard::Result<_>>()?;
    json_map.serialize_entry("mls_hpke_keypairs", &hpke_keypairs)?;

    // openmls's `PskBundle` is private to it, so these are dumped as they're stored.
    let external_psks: std::collections::HashMap<String, String> = keystore
        .load_all::<StoredPskBundle>()
        .await?
        .into_iter()
        .map(|psk| (hex::encode(&psk.psk_id), hex::encode(&psk.psk)))
        .collect();

    json_map.serialize_entry("external_psks", &external_psks)?;

    let keypackages: Vec<openmls::prelude::KeyPackage> = keystore
        .load_all::<StoredKeyPackage>()
        .await?
        .into_iter()
        .map(|kp| postcard::from_bytes::<openmls::prelude::KeyPackage>(&kp.key_package))
        .collect::<postcard::Result<_>>()?;
    json_map.serialize_entry("mls_keypackages", &keypackages)?;

    // openmls's state of each group isn't dumped: it can't be serialized as a whole.
    let all_groups = keystore.load_all::<PersistedMlsGroup>().await?;
    let (pending_groups, groups) = all_groups.into_iter().partition::<Vec<_>, _>(|group| group.is_pending);
    let group_json = |group: &PersistedMlsGroup| {
        serde_json::json!({
            "id": hex::encode(&*group.id),
            "epoch": group.epoch,
            "ciphersuite": group.ciphersuite,
            "credential_id": hex::encode(group.credential_id),
            "credential_type": group.credential_type,
            "credential_not_before": group.credential_not_before,
            "own_leaf_index": group.own_leaf_index,
        })
    };
    json_map.serialize_entry("mls_groups", &groups.iter().map(|g| group_json(g)).collect::<Vec<_>>())?;
    json_map.serialize_entry(
        "mls_pending_groups",
        &pending_groups.iter().map(|g| group_json(g)).collect::<Vec<_>>(),
    )?;

    if let Some(proteus_identity) = keystore.get_unique::<ProteusIdentity>().await? {
        let identity = {
            let sk = proteus_identity.sk_raw()?;
            let pk = proteus_identity.pk_raw()?;
            proteus_wasm::keys::IdentityKeyPair::from_raw_key_pair(*sk, *pk)?
        };
        json_map.serialize_entry("proteus_identity", &identity)?;

        let prekeys: Vec<proteus_wasm::keys::PreKey> = keystore
            .load_all::<ProteusPrekey>()
            .await?
            .into_iter()
            .map(|pk| proteus_wasm::keys::PreKey::deserialise(&pk.prekey))
            .collect::<Result<Vec<_>, proteus_wasm::DecodeError>>()?;
        json_map.serialize_entry("proteus_prekeys", &prekeys)?;

        let proteus_sessions: Vec<proteus_wasm::session::Session<proteus_wasm::keys::IdentityKeyPair>> = keystore
            .load_all::<ProteusSession>()
            .await?
            .into_iter()
            .map(|session| proteus_wasm::session::Session::deserialise(identity.clone(), &session.session))
            .collect::<Result<Vec<_>, proteus_wasm::DecodeError>>()?;

        json_map.serialize_entry("proteus_sessions", &proteus_sessions)?;
    }

    json_map.end()?;

    Ok(())
}
