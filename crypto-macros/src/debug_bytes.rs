extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, quote};
use syn::{Data, DeriveInput, Fields, FieldsNamed, FieldsUnnamed, Ident, Type, parse_macro_input};

pub(crate) fn derive_debug(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let struct_sensitive = input.attrs.iter().any(|attr| attr.path().is_ident("sensitive"));

    let debug_body = match input.data {
        Data::Struct(s) => match s.fields {
            Fields::Named(named) => expand_named_fields(&name, &named, struct_sensitive),
            Fields::Unnamed(unnamed) => expand_unnamed_fields(&name, &unnamed, struct_sensitive),
            Fields::Unit => {
                quote! { f.debug_tuple(stringify!(#name)).finish() }
            }
        },
        _ => unimplemented!("Custom Debug only works for structs"),
    };

    let expanded = quote! {
        impl core::fmt::Debug for #name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                #debug_body
            }
        }

        impl log::kv::ToValue for #name {
            fn to_value(&self) -> log::kv::Value<'_> {
                log::kv::Value::from_debug(self)
            }
        }
    };

    TokenStream::from(expanded)
}

enum BytesType {
    Bytes,
    OptionalBytes,
    Other,
}

fn parse_type(ty: &Type) -> BytesType {
    let mut type_string = ty.into_token_stream().to_string();
    type_string.retain(|c| !c.is_whitespace());
    match type_string.as_str() {
        "Option<Vec<u8>>" => BytesType::OptionalBytes,
        "Vec<u8>" => BytesType::Bytes,
        _ => BytesType::Other,
    }
}

fn expand_named_fields(name: &Ident, named: &FieldsNamed, struct_sensitive: bool) -> TokenStream2 {
    let field_debugs = named.named.iter().map(|field| {
        let field_name = field.ident.as_ref().unwrap();
        let field_str = field_name.to_string();

        match (struct_sensitive || is_sensitive(field), parse_type(&field.ty)) {
            (false, BytesType::Bytes) => quote! {
                .field(#field_str, &format_args!("0x{}", hex::encode(&self.#field_name)))
            },
            (false, BytesType::OptionalBytes) => quote! {
                .field(#field_str,
                    &{ // format_args creates a temporary value that is freed too early, so allocate here
                        if let Some(v) = &self.#field_name {
                            format!("Some(0x{})", hex::encode(v))
                        } else {
                            "None".to_string()
                        }
                    }
                )
            },
            (false, BytesType::Other) => quote! {
                .field(#field_str, &self.#field_name)
            },
            (true, _) => quote! {
                .field(#field_str, &obfuscate::Obfuscated::from(&self.#field_name))
            },
        }
    });

    quote! {
        f.debug_struct(stringify!(#name))
            #(#field_debugs)*
            .finish()
    }
}

fn expand_unnamed_fields(name: &Ident, unnamed: &FieldsUnnamed, struct_sensitive: bool) -> TokenStream2 {
    let field_debugs = unnamed.unnamed.iter().enumerate().map(|(i, field)| {
        let index = syn::Index::from(i); // tuple index

        match (struct_sensitive || is_sensitive(field), parse_type(&field.ty)) {
            (false, BytesType::Bytes) => quote! {
                .field(&format_args!("0x{}", hex::encode(&self.#index)))
            },
            (false, BytesType::OptionalBytes) => quote! {
                .field(
            &{ // format_args creates a temporary value that is freed to early, so we allocate memory here
                if let Some(v) = &self.#index {
                    format!("Some(0x{})", hex::encode(v))
                } else {
                    "None".to_string()
                }
             })
            },
            (false, BytesType::Other) => quote! {
                .field(&self.#index)
            },
            (true, _) => quote! {
                .field(&obfuscate::Obfuscated::from(&self.#index))
            },
        }
    });

    quote! {
        f.debug_tuple(stringify!(#name))
            #(#field_debugs)*
            .finish()
    }
}

fn is_sensitive(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| attr.path().is_ident("sensitive"))
}
