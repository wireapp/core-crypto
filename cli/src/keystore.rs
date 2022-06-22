use openmls::prelude::*;
use openmls_traits::key_store::{FromKeyStoreValue, ToKeyStoreValue};

use std::io::Write;
use std::path::{Path, PathBuf};
use tempdir::TempDir;

pub struct TestKeyStore {
    path: PathBuf,
}

impl TestKeyStore {
    fn create<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        std::fs::create_dir_all(&path)?;
        Ok(TestKeyStore {
            path: path.as_ref().to_path_buf(),
        })
    }

    fn key_path(&self, k: &[u8]) -> PathBuf {
        let mut path = self.path.clone();
        path.push(base64::encode(k));
        path
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TestKeyStoreError(String);

impl Into<String> for TestKeyStoreError {
    fn into(self) -> String {
        self.0
    }
}

impl From<String> for TestKeyStoreError {
    fn from(e: String) -> Self {
        Self(e)
    }
}

impl From<std::io::Error> for TestKeyStoreError {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

impl OpenMlsKeyStore for TestKeyStore {
    type Error = TestKeyStoreError;

    fn store<V: ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let mut file = std::fs::File::create(self.key_path(k))?;
        let value = v.to_key_store_value().map_err(|e| e.into())?;
        file.write(&value)?;
        Ok(())
    }

    fn read<V: FromKeyStoreValue>(&self, k: &[u8]) -> Option<V> {
        let buf = std::fs::read(self.key_path(k)).ok()?;
        V::from_key_store_value(&buf).ok()
    }

    fn delete(&self, k: &[u8]) -> Result<(), Self::Error> {
        std::fs::remove_file(self.key_path(k))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[derive(Debug, PartialEq)]
    struct Value(Vec<u8>);

    impl Value {
        fn from_slice(v: &[u8]) -> Self {
            Value(v.to_vec())
        }
    }

    impl FromKeyStoreValue for Value {
        type Error = String;

        fn from_key_store_value(v: &[u8]) -> Result<Self, String> {
            Ok(Self(v.to_vec()))
        }
    }

    impl ToKeyStoreValue for Value {
        type Error = String;

        fn to_key_store_value(&self) -> Result<Vec<u8>, String> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn test_store_and_read() {
        let p = TempDir::new("store").unwrap();
        let ks = TestKeyStore::create(&p).unwrap();

        let value = Value::from_slice(b"hello");
        ks.store(b"foo", &value).unwrap();
        assert_eq!(Some(value), ks.read(b"foo"));
    }

    #[test]
    fn test_delete() {
        let p = TempDir::new("store").unwrap();
        let ks = TestKeyStore::create(&p).unwrap();

        let value = Value::from_slice(b"hello");
        ks.store(b"foo", &value).unwrap();
        assert_eq!(Some(value), ks.read(b"foo"));
        ks.delete(b"foo").unwrap();
        assert_eq!(None, ks.read::<Value>(b"foo"));
    }
}
