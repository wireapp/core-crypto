extern crate proc_macro;

use proc_macro::TokenStream;

/// Will drop current MLS group in memory and replace it with the one in the keystore.
/// This simulates an application crash. Once restarted, everything has to be loaded from the
/// keystore, memory is lost.
///
/// Requires the [core_crypto::MlsConversation] method to have a parameter exactly like `backend: &MlsCryptoProvider`
///
/// This helps spotting:
/// * when one has forgotten to call [core_crypto::MlsConversation::persist_group_when_changed]
/// * if persisted fields are sufficient to pursue normally after a crash
///
/// **IF** you mark a method `#[durable]`, remove its call to
/// [core_crypto::MlsConversation::persist_group_when_changed] and tests still pass, you either:
/// * have unit tests not covering the method enough
/// * do not require this method to be durable
#[proc_macro_attribute]
pub fn durable(_args: TokenStream, item: TokenStream) -> TokenStream {
    const ASYNC_ERROR_MSG: &str = "Since a durable method requires persistence in the keystore, it has to be async";

    let ast = match syn::parse2::<syn::ItemFn>(item.clone().into()) {
        Ok(ast) => ast,
        Err(e) => return compile_error(item, e),
    };
    if ast.sig.asyncness.is_none() {
        return compile_error(item, syn::Error::new_spanned(ast, ASYNC_ERROR_MSG));
    }

    let doc_attributes = ast
        .attrs
        .iter()
        .filter(|attr| attr.path.is_ident("doc"))
        .cloned()
        .collect::<Vec<syn::Attribute>>();

    let ret = &ast.sig.output;
    let name = &ast.sig.ident;
    let inputs = &ast.sig.inputs;
    let body = &ast.block;
    let attrs = &ast.attrs;
    let vis = &ast.vis;

    let result: proc_macro2::TokenStream = quote::quote! {
        #(#doc_attributes)*
        #(#attrs)*
        #vis async fn #name(#inputs) #ret {
            let _result = #body;
            #[cfg(test)] {
                self.drop_and_restore(backend).await;
            }
            _result
        }
    };
    result.into()
}

fn compile_error(mut item: TokenStream, err: syn::Error) -> TokenStream {
    let compile_err = TokenStream::from(err.to_compile_error());
    item.extend(compile_err);
    item
}
