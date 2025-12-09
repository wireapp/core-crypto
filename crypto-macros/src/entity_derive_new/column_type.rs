use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{Type, parse_quote};

fn string_types() -> [Type; 3] {
    [
        parse_quote!(String),
        parse_quote!(std::string::String),
        parse_quote!(core::string::String),
    ]
}

fn bytes_types() -> [Type; 3] {
    [
        parse_quote!(Vec<u8>),
        parse_quote!(std::vec::Vec<u8>),
        parse_quote!(core::vec::Vec<u8>),
    ]
}

fn optional_types(ty: &Type) -> [Type; 3] {
    [
        parse_quote!(Option<#ty>),
        parse_quote!(std::option::Option<#ty>),
        parse_quote!(core::option::Option<#ty>),
    ]
}

/// Legal types for an ID column
#[derive(PartialEq, Eq)]
pub(super) enum IdColumnType {
    String,
    Bytes,
}

impl TryFrom<Type> for IdColumnType {
    type Error = syn::Error;

    fn try_from(ty: Type) -> Result<Self, Self::Error> {
        if string_types().contains(&ty) {
            Ok(Self::String)
        } else if bytes_types().contains(&ty) {
            Ok(Self::Bytes)
        } else {
            let type_string = ty.to_token_stream().to_string();
            Err(syn::Error::new_spanned(
                ty,
                format!("Expected `String` or `Vec<u8>`, not `{type_string}`"),
            ))
        }
    }
}

impl IdColumnType {
    /// emit the owned form of this type
    pub(super) fn owned(&self) -> TokenStream {
        match self {
            Self::String => quote!(String),
            Self::Bytes => quote!(Vec<u8>),
        }
    }

    /// emit the borrowed form of this type
    ///
    /// Note that this is emitted _without_ a leading `&`
    pub(super) fn borrowed(&self) -> TokenStream {
        match self {
            Self::String => quote!(str),
            Self::Bytes => quote!([u8]),
        }
    }
}

/// Legal types for any other column
#[derive(PartialEq, Eq)]
pub(super) enum ColumnType {
    String,
    Bytes,
    OptionalBytes,
}

impl TryFrom<Type> for ColumnType {
    type Error = syn::Error;

    fn try_from(ty: Type) -> Result<Self, Self::Error> {
        if string_types().contains(&ty) {
            Ok(Self::String)
        } else if bytes_types().contains(&ty) {
            Ok(Self::Bytes)
        } else if bytes_types().iter().flat_map(optional_types).any(|o_type| o_type == ty) {
            Ok(Self::OptionalBytes)
        } else {
            let type_string = ty.to_token_stream().to_string();
            Err(syn::Error::new_spanned(
                ty,
                format!("Expected `String`, `Vec<u8>`, or `Option<Vec<u8>>`, not `{type_string}`"),
            ))
        }
    }
}

pub(super) trait EmitGetExpression {
    /// Emit an expression which wraps the input expression, appropriately parsing according to this column type.
    fn emit_get_expression(&self, input: TokenStream) -> TokenStream;
}

impl EmitGetExpression for IdColumnType {
    fn emit_get_expression(&self, input: TokenStream) -> TokenStream {
        match self {
            Self::Bytes => input,
            Self::String => quote!(String::from_utf8(#input).map_err(|err| err.utf8_error())?),
        }
    }
}

impl EmitGetExpression for ColumnType {
    fn emit_get_expression(&self, input: TokenStream) -> TokenStream {
        match self {
            ColumnType::Bytes => input,
            ColumnType::String => quote!(String::from_utf8(#input).map_err(|err| err.utf8_error())?),
            ColumnType::OptionalBytes => quote! {{
                let data = #input;
                (!data.is_empty).then_some(data)
            }},
        }
    }
}
