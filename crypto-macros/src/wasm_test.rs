use proc_macro::TokenStream;
use quote::quote;

use crate::compile_error;

pub(crate) fn wasm_bindgen_test(item: TokenStream) -> TokenStream {
    let mut test = match syn::parse2::<syn::ItemFn>(item.clone().into()) {
        Ok(test) => test,
        Err(error) => return compile_error(item, error),
    };

    if test.sig.asyncness.is_none() {
        return compile_error(
            item,
            syn::Error::new_spanned(&test.sig, "a JSPI WebAssembly test must be async"),
        );
    }

    let body = test.block;
    test.block = Box::new(syn::parse_quote!({
        let __jspi_test_output = ::std::rc::Rc::new(::std::cell::RefCell::new(None));
        let __jspi_test_result = __jspi_test_output.clone();
        let mut __jspi_test = Some(async move #body);
        let __jspi_test_completion = ::js_sys::Promise::new(&mut |resolve, _reject| {
            let __jspi_test = __jspi_test.take().expect("promise executor runs once");
            let __jspi_test_result = __jspi_test_result.clone();
            ::sqlite_wasm_vfs::opfs_jspi::defer(move || {
                let __jspi_test_promise = ::wasm_bindgen_futures::future_to_promise(async move {
                    *__jspi_test_result.borrow_mut() = Some(__jspi_test.await);
                    Ok(::wasm_bindgen::JsValue::UNDEFINED)
                });
                resolve
                    .call1(&::wasm_bindgen::JsValue::UNDEFINED, &__jspi_test_promise)
                    .unwrap();
            });
        });
        ::wasm_bindgen_futures::JsFuture::from(__jspi_test_completion)
            .await
            .unwrap();
        let __jspi_test_output = __jspi_test_output
            .borrow_mut()
            .take()
            .expect("JSPI test completed without a result");
        __jspi_test_output
    }));
    test.attrs
        .insert(0, syn::parse_quote!(#[::wasm_bindgen_test::wasm_bindgen_test]));

    quote!(#test).into()
}
