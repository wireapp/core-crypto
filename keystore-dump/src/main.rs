#[cfg(not(target_family = "wasm"))]
use anyhow::{anyhow, bail};

#[cfg(target_family = "wasm")]
fn main() -> anyhow::Result<()> {
    println!("the keystore dump tool is not available for WASM");
    Ok(())
}

#[cfg(not(target_family = "wasm"))]
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

    use chrono::TimeZone;
    use clap::Parser as _;
    use core_crypto_keystore::{
        ConnectionType, Database as Keystore, DatabaseKey, entities::*, traits::FetchFromDatabase,
    };
    use openmls::prelude::TlsDeserializeTrait;
    use serde::ser::{SerializeMap, Serializer};
    use wire_e2e_identity::legacy::E2eiEnrollment;

    let args = Args::parse();

    if !std::path::Path::new(&args.path).exists() {
        bail!("File not found: {}", args.path);
    }

    let key = DatabaseKey::try_from(hex::decode(&args.key)?.as_slice())?;
    let keystore = Keystore::open(ConnectionType::Persistent(&args.path), &key)
        .await
        .map_err(|e| anyhow!("The passkey is probably wrong; [err: {e}]"))?;

    let mut json_serializer = serde_json::Serializer::pretty(std::io::stdout());
    let mut json_map = json_serializer.serialize_map(None)?;

    let mut credentials: Vec<serde_json::Value> = vec![];
    for cred in keystore.load_all::<StoredCredential>().await?.into_iter() {
        let mls_credential = openmls::prelude::Credential::tls_deserialize(&mut cred.credential.as_slice())?;
        let mls_keypair = openmls_basic_credential::SignatureKeyPair::from_raw(
            core_crypto::Ciphersuite::try_from(cred.ciphersuite)
                .expect("ciphersuite from db")
                .signature_algorithm(),
            cred.private_key.to_owned(),
            cred.public_key.to_owned(),
        );
        let date = chrono::Utc
            .timestamp_opt(cred.created_at as i64, 0)
            .single()
            .ok_or_else(|| anyhow!("Cannot parse credential creation date"))?;

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
        .map(|hpke_sk| postcard::from_bytes::<openmls_traits::types::HpkePrivateKey>(&hpke_sk.sk))
        .collect::<postcard::Result<_>>()?;
    json_map.serialize_entry("mls_hpke_private_keys", &hpke_sks)?;

    let hpke_keypairs: Vec<openmls_traits::types::HpkeKeyPair> = keystore
        .load_all::<StoredEncryptionKeyPair>()
        .await?
        .into_iter()
        .map(|hpke_kp| postcard::from_bytes::<openmls_traits::types::HpkeKeyPair>(&hpke_kp.sk))
        .collect::<postcard::Result<_>>()?;
    json_map.serialize_entry("mls_hpke_keypairs", &hpke_keypairs)?;

    let mut external_psks: std::collections::HashMap<String, openmls::schedule::psk::PskBundle> = Default::default();
    for psk in keystore.load_all::<StoredPskBundle>().await?.into_iter() {
        let mls_psk = postcard::from_bytes::<openmls::schedule::psk::PskBundle>(&psk.psk)?;
        external_psks.insert(hex::encode(&psk.psk_id), mls_psk);
    }

    json_map.serialize_entry("external_psks", &external_psks)?;

    let keypackages: Vec<openmls::prelude::KeyPackage> = keystore
        .load_all::<StoredKeypackage>()
        .await?
        .into_iter()
        .map(|kp| postcard::from_bytes::<openmls::prelude::KeyPackage>(&kp.keypackage))
        .collect::<postcard::Result<_>>()?;
    json_map.serialize_entry("mls_keypackages", &keypackages)?;

    let e2ei_enrollments: Vec<E2eiEnrollment> = keystore
        .load_all::<StoredE2eiEnrollment>()
        .await?
        .into_iter()
        .map(|enrollment| serde_json::from_slice::<E2eiEnrollment>(&enrollment.content))
        .collect::<serde_json::Result<_>>()?;
    json_map.serialize_entry("e2ei_enrollments", &e2ei_enrollments)?;

    let pgroups: Vec<openmls::prelude::MlsGroup> = keystore
        .load_all::<PersistedMlsGroup>()
        .await?
        .into_iter()
        .map(|pgroup| core_crypto_keystore::deser::<openmls::prelude::MlsGroup>(&pgroup.state))
        .collect::<core_crypto_keystore::CryptoKeystoreResult<_>>()?;
    json_map.serialize_entry("mls_groups", &pgroups)?;

    let pegroups: Vec<openmls::prelude::MlsGroup> = keystore
        .load_all::<PersistedMlsPendingGroup>()
        .await?
        .into_iter()
        .map(|pgroup| core_crypto_keystore::deser::<openmls::prelude::MlsGroup>(&pgroup.state))
        .collect::<core_crypto_keystore::CryptoKeystoreResult<_>>()?;
    json_map.serialize_entry("mls_pending_groups", &pegroups)?;

    if let Some(proteus_identity) = keystore.get_unique::<ProteusIdentity>().await? {
        let identity = {
            let sk = proteus_identity.sk_raw();
            let pk = proteus_identity.pk_raw();
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
