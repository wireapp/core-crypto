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
        ::core_crypto_keystore::connection::run_in_jspi(async move #body).await
    }));
    test.attrs
        .insert(0, syn::parse_quote!(#[::wasm_bindgen_test::wasm_bindgen_test]));

    quote!(#test).into()
}
