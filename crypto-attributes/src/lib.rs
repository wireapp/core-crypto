extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Ident;
use syn::{punctuated::Punctuated, token::Comma, Attribute, Block, FnArg, ItemFn, ReturnType, Visibility};

mod durable;
mod idempotent;

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
    durable::durable(item)
}

/// !!! Not literally idempotent !!!
/// Marker for methods on 'MlsCentral' which leave the number of entities in the keystore even.
/// They can create/destroy some but always compensate.
/// So they are not idempotent, they cannot be safely replayed and they might leave the keystore in
/// a different state.
#[proc_macro_attribute]
pub fn idempotent(_args: TokenStream, item: TokenStream) -> TokenStream {
    idempotent::idempotent(item)
}

/// Neologism to mean the opposite of idempotent. Methods of 'MlsCentral' marked with this have to
/// insert/delete an entity in the keystore and change the number of entities persisted.
#[proc_macro_attribute]
pub fn dispotent(_args: TokenStream, item: TokenStream) -> TokenStream {
    idempotent::dispotent(item)
}

pub(crate) fn doc_attributes(ast: &ItemFn) -> Vec<Attribute> {
    ast.attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .cloned()
        .collect::<Vec<syn::Attribute>>()
}

pub(crate) fn compile_error(mut item: TokenStream, err: syn::Error) -> TokenStream {
    let compile_err = TokenStream::from(err.to_compile_error());
    item.extend(compile_err);
    item
}

#[allow(clippy::type_complexity)]
pub(crate) fn items(
    ast: &ItemFn,
) -> (
    &ReturnType,
    &Ident,
    &Punctuated<FnArg, Comma>,
    &Box<Block>,
    &Vec<Attribute>,
    &Visibility,
) {
    let ret = &ast.sig.output;
    let name = &ast.sig.ident;
    let inputs = &ast.sig.inputs;
    let body = &ast.block;
    let attrs = &ast.attrs;
    let vis = &ast.vis;
    (ret, name, inputs, body, attrs, vis)
}
