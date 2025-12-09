mod column;
mod column_type;
mod derive_impl;
mod field_transformation;
mod is_id;
mod parse;

use darling::FromDeriveInput;
use field_transformation::FieldTransformation;
use heck::ToSnakeCase;
use proc_macro2::Ident;
use syn::Visibility;

use crate::entity_derive_new::{
    column::{Column, IdColumn},
    is_id::parse_columns,
};

/// Less abstract version of [parse::Entity] that has all the fields flattened
/// ready for usage in `quote!()`.
pub(super) struct Entity {
    // This will be necessary for WPB-22192 and WPB-22193
    #[expect(dead_code)]
    visibility: Visibility,
    struct_name: Ident,
    collection_name: String,
    id_column: IdColumn,
    other_columns: Vec<Column>,
}

impl TryFrom<parse::Entity> for Entity {
    type Error = syn::Error;

    fn try_from(value: parse::Entity) -> Result<Self, Self::Error> {
        let parse::Entity {
            vis: visibility,
            ident: struct_name,
            outer_attributes,
            data,
        } = value;

        let collection_name = outer_attributes
            .collection_name
            .unwrap_or_else(|| struct_name.to_string().to_snake_case() + "s");

        let (id_column, other_columns) = parse_columns(struct_name.span(), data)?;

        Ok(Self {
            visibility,
            struct_name,
            collection_name,
            id_column,
            other_columns,
        })
    }
}

impl FromDeriveInput for Entity {
    fn from_derive_input(input: &syn::DeriveInput) -> darling::Result<Self> {
        let entity = parse::Entity::from_derive_input(input)?;
        entity.try_into().map_err(Into::into)
    }
}
