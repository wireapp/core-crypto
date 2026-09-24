// How `relaxed-idb-vfs-v10.5.3.json` was produced. Not compiled: this is a wasm-bindgen integration test written
// against the v10.5.3 keystore API, and only builds in a checkout of that tag. See README.md alongside for the
// procedure.

use std::sync::Arc;

use wasm_bindgen::{JsValue, UnwrapThrowExt as _};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;

use core_crypto_keystore::{Database, DatabaseKey};

wasm_bindgen_test_configure!(run_in_browser);

const DATABASE_NAME: &str = "corecrypto.cc10-vfs-fixture.v10_5_3";
const VFS_DATABASE_NAME: &str = "core-crypto";
const DATABASE_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const DUMP_JS: &str = r#"(async function (vfsName) {
  const open = (name) => new Promise((resolve, reject) => {
    const req = indexedDB.open(name);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);
  });
  const request = (req) => new Promise((resolve, reject) => {
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);
  });
  const enc = (v) => {
    if (v instanceof Uint8Array) return { "$u8": Array.from(v).map((b) => b.toString(16).padStart(2, "0")).join("") };
    if (v instanceof ArrayBuffer) return enc(new Uint8Array(v));
    if (Array.isArray(v)) return v.map(enc);
    if (v === null || typeof v !== "object") return v;
    if (ArrayBuffer.isView(v)) throw new Error("unexpected typed array " + v.constructor.name);
    const o = {};
    for (const k of Object.keys(v)) o[k] = enc(v[k]);
    return o;
  };

  const deadline = Date.now() + 10_000;
  for (;;) {
    const db = await open(vfsName);
    const tx = db.transaction(["blocks"], "readonly");
    const store = tx.objectStore("blocks");
    const [keys, values] = await Promise.all([
      request(store.getAllKeys()),
      request(store.getAll()),
    ]);
    db.close();
    if (keys.length > 0) {
      const i = keys.findIndex((key) => key[0] === "corecrypto.cc10-vfs-fixture.v10_5_3" && key[1] === 0);
      if (i < 0) throw new Error("the initialized database has no offset-zero page");
      return JSON.stringify({
        version: 1,
        store: "blocks",
        row: { key: enc(keys[i]), value: enc(values[i]) },
      });
    }
    if (Date.now() >= deadline) throw new Error("timed out waiting for relaxed-idb writes");
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
})"#;

#[wasm_bindgen_test]
async fn dump_cc10_vfs_fixture() {
    let factory = idb::Factory::new().unwrap_throw();
    factory
        .delete(VFS_DATABASE_NAME)
        .unwrap_throw()
        .await
        .unwrap_throw();

    let key = DatabaseKey::try_from(hex::decode(DATABASE_KEY_HEX).unwrap_throw()).unwrap_throw();
    let db = Database::open(DATABASE_NAME, &key).await.unwrap_throw();
    Arc::into_inner(db).unwrap_throw().close().await.unwrap_throw();

    let dump: js_sys::Function = js_sys::eval(DUMP_JS).unwrap_throw().into();
    let promise: js_sys::Promise = dump
        .call1(&JsValue::NULL, &JsValue::from_str(VFS_DATABASE_NAME))
        .unwrap_throw()
        .into();
    let json = JsFuture::from(promise)
        .await
        .unwrap_throw()
        .as_string()
        .unwrap_throw();

    panic!(
        "FIXTURE_BEGIN\n{{\"generated_by\":\"v10.5.3\",\"database_name\":\"{DATABASE_NAME}\",\"database_key\":\"{DATABASE_KEY_HEX}\",{}\nFIXTURE_END",
        &json[1..]
    );
}
