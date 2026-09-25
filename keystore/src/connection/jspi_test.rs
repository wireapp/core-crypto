//! Runs async tests where they can use synchronous JSPI APIs.

use std::{cell::RefCell, rc::Rc};

use js_sys::{Function, Promise, Reflect};
use wasm_bindgen::{JsCast as _, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::{JsFuture, spawn_local};

use super::opfs_vfs::defer;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = addEventListener)]
    fn add_event_listener(kind: &str, listener: &Function);
    #[wasm_bindgen(js_name = removeEventListener)]
    fn remove_event_listener(kind: &str, listener: &Function);
}

/// Runs `future` to completion inside the keystore's JSPI export, so that every poll can suspend.
///
/// Used by `core_crypto_macros::jspi_wasm_bindgen_test`.
///
/// The future runs in a separate JSPI task, outside wasm-bindgen-test's panic-catching trampoline. If it panics, the
/// task traps and never finishes, so on its own the test would wait until the runner times out.
///
/// js-sys enters each poll of that task through a promise it doesn't handle, so the trap shows up as an
/// `unhandledrejection` event on `globalThis`. For as long as the future runs, we listen for that event and reject the
/// completion promise with its reason. We await that promise and panic on rejection. That panic happens inside the
/// trampoline, so the runner reports the test as failed and goes on.
///
/// A panic hook can't do this: under panic=abort, std considers the thread to be panicking forever after the first
/// panic, and from then on refuses to change hooks.
#[doc(hidden)]
pub async fn run_in_jspi<F>(future: F) -> F::Output
where
    F: 'static + Future,
{
    let reject = Rc::new(RefCell::new(None::<Function>));
    let on_unhandled_rejection = {
        let reject = reject.clone();
        Closure::<dyn FnMut(JsValue)>::new(move |event: JsValue| {
            if let Some(reject) = reject.borrow_mut().take() {
                let reason = Reflect::get(&event, &"reason".into()).unwrap_or(JsValue::UNDEFINED);
                let _ = reject.call1(&JsValue::UNDEFINED, &reason);
            }
        })
    };
    let listener = on_unhandled_rejection.as_ref().unchecked_ref::<Function>();
    add_event_listener("unhandledrejection", listener);

    let output = Rc::new(RefCell::new(None));
    let mut future = Some(future);
    let completion = Promise::new(&mut |resolve, reject_completion| {
        *reject.borrow_mut() = Some(reject_completion);
        let future = future.take().expect("promise executor runs once");
        let output = output.clone();
        defer(move || {
            // Resolve only once the future has finished: a promise which has been resolved with another promise
            // ignores a later rejection, so an aborted future could no longer be reported.
            spawn_local(async move {
                *output.borrow_mut() = Some(future.await);
                resolve.call0(&JsValue::UNDEFINED).unwrap();
            });
        });
    });
    let completed = JsFuture::from(completion).await;
    remove_event_listener("unhandledrejection", listener);
    if let Err(reason) = completed {
        panic!("JSPI test body aborted; any panic message is logged above: {reason:?}");
    }

    output.take().expect("JSPI test completed without a result")
}
