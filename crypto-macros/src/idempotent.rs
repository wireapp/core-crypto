use crate::{compile_error, doc_attributes, items};
use proc_macro::TokenStream;

const ASYNC_ERROR_MSG: &str = "This requires access to the keystore, it has to be async";

pub(crate) fn idempotent(item: TokenStream) -> TokenStream {
    let ast = match syn::parse2::<syn::ItemFn>(item.clone().into()) {
        Ok(ast) => ast,
        Err(e) => return compile_error(item, e),
    };
    if ast.sig.asyncness.is_none() {
        return compile_error(item, syn::Error::new_spanned(ast, ASYNC_ERROR_MSG));
    }

    let doc_attributes = doc_attributes(&ast);
    let (ret, name, inputs, body, attrs, vis) = items(&ast);

    let result: proc_macro2::TokenStream = quote::quote! {
        #(#doc_attributes)*
        #(#attrs)*
        #vis async fn #name(#inputs) #ret {
            let prev_count = self.count_entities().await;

            let _result = #body;

            let next_count = self.count_entities().await;
            assert_eq!(prev_count, next_count, "'{}()' leaks entities", stringify!(#name));

            _result
        }
    };
    result.into()
}

pub(crate) fn dispotent(item: TokenStream) -> TokenStream {
    let ast = match syn::parse2::<syn::ItemFn>(item.clone().into()) {
        Ok(ast) => ast,
        Err(e) => return compile_error(item, e),
    };
    if ast.sig.asyncness.is_none() {
        return compile_error(item, syn::Error::new_spanned(ast, ASYNC_ERROR_MSG));
    }

    let doc_attributes = doc_attributes(&ast);
    let (ret, name, inputs, body, attrs, vis) = items(&ast);

    let result: proc_macro2::TokenStream = quote::quote! {
        #(#doc_attributes)*
        #(#attrs)*
        #vis async fn #name(#inputs) #ret {
            let prev_count = self.count_entities().await;

            let _result = #body;

            let next_count = self.count_entities().await;
            assert_ne!(prev_count, next_count, "'{}()' does not create entities", stringify!(#name));

            _result
        }
    };
    result.into()
}
