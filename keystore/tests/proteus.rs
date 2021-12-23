mod common;

#[cfg(test)]
mod tests {
    use super::common::*;
    use proteus::keys::{PreKey, PreKeyId};

    #[test]
    fn can_add_read_delete_prekey() {
        let mut store = setup("proteus");
        let prekey_id = PreKeyId::new(28273);
        let prekey = PreKey::new(prekey_id);
        store.store_prekey(prekey.clone()).unwrap();
        use proteus::session::PreKeyStore as _;
        let _ = store.prekey(prekey_id).unwrap().unwrap();
        let _ = store.remove(prekey.key_id).unwrap();
        teardown("proteus");
    }
}
