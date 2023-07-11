use crate::{compile_error, doc_attributes, items};
use proc_macro::TokenStream;

pub(crate) fn durable(item: TokenStream) -> TokenStream {
    const ASYNC_ERROR_MSG: &str = "Since a durable method requires persistence in the keystore, it has to be async";

    let ast = match syn::parse2::<syn::ItemFn>(item.clone().into()) {
        Ok(ast) => ast,
        Err(e) => return compile_error(item, e),
    };
    if ast.sig.asyncness.is_none() {
        return compile_error(item, syn::Error::new_spanned(ast, ASYNC_ERROR_MSG));
    }

    let doc_attributes = doc_attributes(&ast);
    let (ret, name, inputs, body, attrs, vis) = items(&ast);

    let func: proc_macro2::TokenStream = quote::quote! {
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
    func.into()
}
