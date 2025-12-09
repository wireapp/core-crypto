use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::Type;

use super::{
    FieldTransformation,
    column_type::{ColumnType, IdColumnType},
};
use crate::entity_derive_new::column_type::EmitGetExpression;

pub(super) struct GenericColumn<Type> {
    pub(super) field_name: Ident,
    pub(super) column_type: Type,
    /// Only present if it differs from the field name
    pub(super) column_name: Option<String>,
    /// If the ID is transformed for storage within the DB
    pub(super) transformation: Option<FieldTransformation>,
}

pub(super) type Column = GenericColumn<ColumnType>;
pub(super) type IdColumn = GenericColumn<IdColumnType>;

impl<CType> TryFrom<super::parse::Column> for GenericColumn<CType>
where
    CType: TryFrom<Type>,
    syn::Error: From<<CType as TryFrom<Type>>::Error>,
{
    type Error = syn::Error;

    fn try_from(value: super::parse::Column) -> Result<Self, Self::Error> {
        let field_name = value
            .ident
            .expect("we have nice error messages from `supports(struct_named)");
        let column_type = CType::try_from(value.ty)?;
        let transformation = value.field_attrs.transformation();
        let column_name = value.field_attrs.column;

        Ok(Self {
            field_name,
            column_type,
            column_name,
            transformation,
        })
    }
}

impl<Type> GenericColumn<Type>
where
    Type: EmitGetExpression,
{
    /// Emit a load expression.
    ///
    /// This assumes that a value `row: rusqlite::Row` is in scope,
    /// and the containing scope can handle early returns of type `rusqlite::Error`
    pub(super) fn load_expression(&self) -> TokenStream {
        let column_name = self.column_name.clone().unwrap_or_else(|| self.field_name.to_string());

        let expr = quote!(row.get::<_, Vec<u8>>(#column_name)?);

        let expr = match self.transformation {
            None => expr,
            Some(FieldTransformation::Hex) => {
                quote!(hex::decode(#expr).map_err(|err| rusqlite::Error::UserFunctionError(err.into()))?)
            }
        };

        self.column_type.emit_get_expression(expr)
    }

    /// Emit a field assignment.
    ///
    /// This is just the pair `field_name: load_expression`. Note the absence of trailing comma!
    ///
    /// Includes all assumptions from [`Self::load_expression`] and the additional assumption that this is being
    /// called within the body of a struct literal.
    pub(super) fn field_assignment(&self) -> TokenStream {
        let field_name = &self.field_name;
        let load_expression = self.load_expression();
        quote!(#field_name: #load_expression)
    }
}
