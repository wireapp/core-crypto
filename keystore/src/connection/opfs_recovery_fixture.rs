//! Browser-only fixture for recovery from a committed WAL left by page termination.
//! Enabled solely by the standalone example, never by the application build.

use std::{cell::RefCell, sync::Arc};

use js_sys::{Function, Reflect};
use wasm_bindgen::JsValue;

use super::Database;
use crate::DatabaseKey;

const PAYLOAD_LEN: usize = 4 * 1024 * 1024;

thread_local! {
    static RECOVERED: RefCell<Option<Arc<Database>>> = const { RefCell::new(None) };
}

fn key() -> DatabaseKey {
    DatabaseKey::from([0xA5; DatabaseKey::LEN])
}

pub async fn prepare(name: &str) -> Result<(), String> {
    let db = Database::open(name, &key()).await.map_err(|error| error.to_string())?;
    let conn = db.conn().await;
    conn.pragma_update(None, "wal_autocheckpoint", 0)
        .map_err(|error| error.to_string())?;
    conn.execute_batch("CREATE TABLE recovery_probe(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)")
        .map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO recovery_probe(id, payload) VALUES (1, ?1)",
        [vec![0x5A; PAYLOAD_LEN]],
    )
    .map_err(|error| error.to_string())?;
    drop(conn);

    // The page will reload immediately. Deliberately leave the connection live
    // so SQLite cannot perform its normal close-time checkpoint.
    std::mem::forget(db);
    Ok(())
}

fn install_checkpoint_failure(name: &str) -> Result<JsValue, String> {
    let hook: Function = js_sys::eval(
        r#"(function (name) {
          const physical = 'f-' + Array.from(new TextEncoder().encode(name + '-wal'),
            byte => byte.toString(16).padStart(2, '0')).join('');
          globalThis.__coreCryptoWorkerFault.arm(physical, 'truncate', 0);
          return {
            fired: () => globalThis.__coreCryptoWorkerFault.fired(),
            restore: () => globalThis.__coreCryptoWorkerFault.clear()
          };
        })"#,
    )
    .map_err(|error| format!("evaluating checkpoint hook: {error:?}"))?
    .into();
    hook.call1(&JsValue::NULL, &JsValue::from_str(name))
        .map_err(|error| format!("installing checkpoint hook: {error:?}"))
}

fn call_hook(handle: &JsValue, method: &str) -> Result<JsValue, String> {
    let function: Function = Reflect::get(handle, &JsValue::from_str(method))
        .map_err(|error| format!("reading hook {method}: {error:?}"))?
        .into();
    function
        .call0(&JsValue::NULL)
        .map_err(|error| format!("calling hook {method}: {error:?}"))
}

pub async fn recover(name: &str, fail_checkpoint: bool) -> Result<(), String> {
    if fail_checkpoint {
        let hook = install_checkpoint_failure(name)?;
        let failed_open = Database::open(name, &key()).await;
        call_hook(&hook, "restore")?;
        if call_hook(&hook, "fired")? != JsValue::TRUE {
            return Err("startup did not attempt to truncate the WAL".into());
        }
        if failed_open.is_ok() {
            return Err("open succeeded despite the injected checkpoint error".into());
        }
    }

    let db = Database::open(name, &key()).await.map_err(|error| error.to_string())?;
    let conn = db.conn().await;
    let payload: Vec<u8> = conn
        .query_row("SELECT payload FROM recovery_probe WHERE id = 1", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if payload.len() != PAYLOAD_LEN || payload.iter().any(|byte| *byte != 0x5A) {
        return Err("acknowledged WAL payload changed during recovery".into());
    }
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if integrity != "ok" {
        return Err(format!("integrity_check returned {integrity}"));
    }
    let limit: i64 = conn
        .pragma_query_value(None, "journal_size_limit", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    let autocheckpoint: i64 = conn
        .pragma_query_value(None, "wal_autocheckpoint", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if (limit, autocheckpoint) != (0, 64) {
        return Err(format!("unexpected WAL policy: {limit}, {autocheckpoint}"));
    }
    drop(conn);
    RECOVERED.with_borrow_mut(|slot| *slot = Some(db));
    Ok(())
}

pub async fn finish() -> Result<(), String> {
    let db = RECOVERED.with_borrow_mut(Option::take).ok_or("no recovered database")?;
    db.conn()
        .await
        .execute(
            "INSERT INTO recovery_probe(id, payload) VALUES (2, ?1)",
            [vec![0x33; 16]],
        )
        .map_err(|error| error.to_string())?;
    Arc::into_inner(db)
        .ok_or("recovered database still has another owner")?
        .wipe()
        .await
        .map_err(|error| error.to_string())
}
