//! Derivation of the keychain account names under which the iOS keystore salt is stored.
//!
//! The keychain-facing orchestration lives in [`super::ios_wal_compat`] (iOS only). The logic here
//! is platform-independent so it can be unit-tested on the host.

use sha2::Digest as _;

use crate::CryptoKeystoreResult;

const SALT_ID_LEN: usize = 16;
const SALT_KEY_PREFIX: &str = "keystore_salt_v2_";
const LEGACY_SALT_KEY_PREFIX: &str = "keystore_salt_";

/// Keychain account name keyed by a stable, path-independent id (see [`read_or_create_salt_id`]).
pub(crate) fn stable_salt_keychain_key(db_path: &str) -> CryptoKeystoreResult<String> {
    let id = read_or_create_salt_id(db_path)?;
    Ok(format!("{SALT_KEY_PREFIX}{}", hex::encode(id)))
}

/// Legacy keychain account name keyed by the sha256 of the database's absolute path.
pub(crate) fn legacy_salt_keychain_key(db_path: &str) -> String {
    format!("{LEGACY_SALT_KEY_PREFIX}{}", hex::encode(sha2::Sha256::digest(db_path)))
}

fn salt_id_sidecar_path(db_path: &str) -> String {
    format!("{db_path}.salt-id")
}

fn read_or_create_salt_id(db_path: &str) -> CryptoKeystoreResult<[u8; SALT_ID_LEN]> {
    let sidecar = salt_id_sidecar_path(db_path);

    match std::fs::read(&sidecar) {
        Ok(bytes) if bytes.len() == SALT_ID_LEN => {
            let mut id = [0u8; SALT_ID_LEN];
            id.copy_from_slice(&bytes);
            Ok(id)
        }
        Ok(bytes) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "salt id sidecar {sidecar} is corrupt: expected {SALT_ID_LEN} bytes, found {}",
                bytes.len()
            ),
        )
        .into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_salt_id(&sidecar),
        Err(e) => Err(e.into()),
    }
}

fn create_salt_id(sidecar: &str) -> CryptoKeystoreResult<[u8; SALT_ID_LEN]> {
    use std::io::Write as _;

    let id = rand::random::<[u8; SALT_ID_LEN]>();
    let tmp = format!("{sidecar}.{}.tmp", hex::encode(rand::random::<[u8; 8]>()));

    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(&id)?;
    file.sync_all()?;
    std::fs::rename(&tmp, sidecar)?;

    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db_path(dir: &tempfile::TempDir, name: &str) -> String {
        dir.path().join(name).to_str().unwrap().to_owned()
    }

    #[test]
    fn creates_sidecar_and_reads_stable_id() {
        let dir = tempfile::tempdir().unwrap();
        let db = db_path(&dir, "keystore");

        let id = read_or_create_salt_id(&db).unwrap();

        assert!(std::path::Path::new(&salt_id_sidecar_path(&db)).exists());
        // Reading again returns the same id (idempotent).
        assert_eq!(read_or_create_salt_id(&db).unwrap(), id);
    }

    #[test]
    fn id_and_key_survive_container_move() {
        let dir_before = tempfile::tempdir().unwrap();
        let db_before = db_path(&dir_before, "keystore");
        let id = read_or_create_salt_id(&db_before).unwrap();
        let key = stable_salt_keychain_key(&db_before).unwrap();

        // Simulate iOS relocating the container: the sidecar moves with the database.
        let dir_after = tempfile::tempdir().unwrap();
        let db_after = db_path(&dir_after, "keystore");
        std::fs::rename(salt_id_sidecar_path(&db_before), salt_id_sidecar_path(&db_after)).unwrap();

        assert_eq!(read_or_create_salt_id(&db_after).unwrap(), id);
        assert_eq!(stable_salt_keychain_key(&db_after).unwrap(), key);
    }

    #[test]
    fn corrupt_sidecar_errors_instead_of_regenerating() {
        let dir = tempfile::tempdir().unwrap();
        let db = db_path(&dir, "keystore");
        std::fs::write(salt_id_sidecar_path(&db), b"too-short").unwrap();

        let err = read_or_create_salt_id(&db).unwrap_err();
        assert!(matches!(err, crate::CryptoKeystoreError::IoError(_)));
    }

    #[test]
    fn create_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        read_or_create_salt_id(&db_path(&dir, "keystore")).unwrap();

        let temp_files = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(temp_files, 0);
    }

    #[test]
    fn legacy_key_matches_the_native_scheme() {
        let path = "/var/mobile/Containers/Data/Application/ABC/keystore";
        let expected = format!("keystore_salt_{}", hex::encode(sha2::Sha256::digest(path)));
        assert_eq!(legacy_salt_keychain_key(path), expected);
    }

    #[test]
    fn stable_key_is_v2_prefixed_hex() {
        let dir = tempfile::tempdir().unwrap();
        let key = stable_salt_keychain_key(&db_path(&dir, "keystore")).unwrap();

        let id_hex = key.strip_prefix("keystore_salt_v2_").expect("v2 prefix");
        assert_eq!(id_hex.len(), SALT_ID_LEN * 2);
        assert!(id_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
