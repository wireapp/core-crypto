use openmls::prelude::*;
use openmls_traits::key_store::{FromKeyStoreValue, ToKeyStoreValue};

use std::io::Write;
use std::path::PathBuf;

pub struct TestKeyStore {
    path: PathBuf,
}

impl TestKeyStore {
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
