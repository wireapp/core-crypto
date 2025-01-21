use crate::entity_derive::{Column, ColumnType, Columns, IdColumn, IdColumnType, IdTransformation, KeyStoreEntity};
use heck::ToSnakeCase;
use proc_macro2::{Ident, Span};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::{Attribute, Data, DataStruct, Fields, FieldsNamed, Token, Type};

impl syn::parse::Parse for KeyStoreEntity {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let derive_input = input.parse::<syn::DeriveInput>()?;
        let struct_name = derive_input.ident.clone();

        // #[entity(collection_name = "my_collection", no_upsert)]
        let (mut collection_name, no_upsert) = Self::parse_outer_attributes(&derive_input.attrs)?;
        if collection_name.is_empty() {
            collection_name = struct_name.to_string().to_snake_case() + "s";
        }

        let named_fields = Self::fields_from_data(&derive_input.data, derive_input.span())?;
        let id = IdColumn::parse(named_fields)?;
        let columns = Columns::parse(named_fields, &id.name)?;

        Ok(KeyStoreEntity {
            struct_name,
            collection_name,
            id,
            columns,
            no_upsert,
        })
    }
}

impl KeyStoreEntity {
    fn parse_outer_attributes(attrs: &[Attribute]) -> Result<(String, bool), syn::Error> {
        let mut collection_name = String::new();
        let mut no_upsert = false;
        for attr in attrs {
            if !attr.path().is_ident("entity") {
                continue;
            }
            let meta = &attr.meta;
            let list = meta.require_list()?;
            list.parse_nested_meta(|meta| {
                let ident = meta.path.require_ident()?;
                match ident.to_string().as_str() {
                    "collection_name" => {
                        meta.input.parse::<Token![=]>()?;
                        collection_name = meta.input.parse::<syn::LitStr>()?.value();
                        Ok(())
                    }
                    "no_upsert" => {
                        no_upsert = true;
                        Ok(())
                    }
                    _ => Err(syn::Error::new_spanned(ident, "unknown argument")),
                }
            })?;
        }
        Ok((collection_name, no_upsert))
    }

    fn fields_from_data(data: &Data, span: Span) -> syn::Result<&FieldsNamed> {
        match data {
            Data::Struct(DataStruct {
                fields: Fields::Named(named_fields),
                ..
            }) => Ok(named_fields),
            _ => Err(syn::Error::new(span, "Expected a struct with named fields.")),
        }
    }
}

impl IdColumn {
    fn parse(named_fields: &FieldsNamed) -> syn::Result<Self> {
        let mut id = None;
        let mut implicit_id = None;

        for field in &named_fields.named {
            let name = field
                .ident
                .as_ref()
                .expect("named fields always have identifiers")
                .clone();

            if let Some(attr) = field.attrs.iter().find(|a| a.path().is_ident("id")) {
                let mut column_name = None;
                let mut transformation = None;
                let column_type = IdColumnType::parse(&field.ty)?;

                if let Ok(list) = attr.meta.require_list() {
                    list.parse_nested_meta(|meta| {
                        match meta.path.require_ident()?.to_string().as_str() {
                            "column" => {
                                meta.input.parse::<Token![=]>()?;
                                column_name = Some(meta.input.parse::<syn::LitStr>()?.value());
                            }
                            "hex" => transformation = Some(IdTransformation::Hex),
                            _ => return Err(syn::Error::new_spanned(meta.path, "unknown argument")),
                        }
                        Ok(())
                    })?;
                }

                if id
                    .replace(IdColumn {
                        name,
                        column_type,
                        column_name,
                        transformation,
                    })
                    .is_some()
                {
                    return Err(syn::Error::new_spanned(
                        field,
                        "Ambiguous `#[id]` attributes. Provide exactly one.",
                    ));
                }
            } else if name == "id" {
                let column_type = IdColumnType::parse(&field.ty)?;
                implicit_id = Some(IdColumn {
                    name,
                    column_type,
                    column_name: None,
                    transformation: None,
                });
            }
        }

        id.or(implicit_id).ok_or_else(|| {
            syn::Error::new_spanned(
                named_fields,
                "No field named `id` or annotated `#[id]` attribute provided.",
            )
        })
    }
}

impl IdColumnType {
    fn parse(ty: &Type) -> Result<Self, syn::Error> {
        let mut type_string = ty.to_token_stream().to_string();
        type_string.retain(|c| !c.is_whitespace());
        match type_string.as_str() {
            "String" | "std::string::String" => Ok(Self::String),
            "Vec<u8>" | "std::vec::Vec<u8>" => Ok(Self::Bytes),
            type_string => Err(syn::Error::new_spanned(
                ty,
                format!("Expected `String` or `Vec<u8>`, not `{type_string}`."),
            )),
        }
    }
}

impl Columns {
    fn parse(named_fields: &FieldsNamed, id_column: &Ident) -> syn::Result<Self> {
        let columns = named_fields
            .named
            .iter()
            .filter(|field| field.ident.as_ref() != Some(id_column))
            .map(|field| {
                let field_name = field
                    .ident
                    .as_ref()
                    .expect("named fields always have identifiers")
                    .clone();
                let field_type = ColumnType::parse(&field.ty)?;

                Ok(Column {
                    name: field_name,
                    column_type: field_type,
                })
            })
            .collect::<syn::Result<Vec<_>>>()?;
        if columns.is_empty() {
            return Err(syn::Error::new_spanned(
                named_fields,
                "Provide at least one field to be used as a table column.",
            ));
        }

        Ok(Self(columns))
    }
}

impl ColumnType {
    fn parse(ty: &Type) -> Result<Self, syn::Error> {
        let mut type_string = ty.to_token_stream().to_string();
        type_string.retain(|c| !c.is_whitespace());
        match type_string.as_str() {
            "String" | "std::string::String" => Ok(Self::String),
            "Vec<u8>" | "std::vec::Vec<u8>" => Ok(Self::Bytes),
            "Option<Vec<u8>>"
            | "Option<std::vec::Vec<u8>>"
            | "core::option::Option<Vec<u8>>"
            | "core::option::Option<std::vec::Vec<u8>>"
            | "std::option::Option<Vec<u8>>"
            | "std::option::Option<std::vec::Vec<u8>>" => Ok(Self::OptionalBytes),
            type_string => Err(syn::Error::new_spanned(
                ty,
                format!("Expected `String`, `Vec<u8>`, or `Option<Vec<u8>>` not `{type_string}`."),
            )),
        }
    }
}
