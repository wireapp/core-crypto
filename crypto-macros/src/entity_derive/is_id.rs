use darling::util::SpannedValue;
use proc_macro2::Span;
use syn::Error;

use super::column::{Column, IdColumn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IsId {
    /// This column had the `id` flag set
    Explicit,
    /// This column is named `id`
    Implicit,
    /// This column is not an id
    No,
}

impl super::parse::Column {
    fn is_id(&self) -> IsId {
        if self.field_attrs.id.is_present() {
            IsId::Explicit
        } else if self.ident.as_ref().is_some_and(|ident| ident == "id") {
            IsId::Implicit
        } else {
            IsId::No
        }
    }
}

/// Parse the columns of an entity, splitting the id column from the rest
///
/// `type_span` should be the span covering the type of this entity
pub(super) fn parse_columns(type_span: Span, columns: super::parse::Columns) -> syn::Result<(IdColumn, Vec<Column>)> {
    let mut fields = columns
        .take_struct()
        .ok_or_else(|| Error::new(type_span, "must be a struct"))?
        .fields;

    let mut explicit_id_idx = None;
    let mut implicit_id_idx = None;
    for (idx, field) in fields.iter().enumerate() {
        match field.is_id() {
            IsId::Explicit => {
                let previous = explicit_id_idx.replace(idx);
                if previous.is_some() {
                    return Err(Error::new(
                        field.field_attrs.id.span(),
                        "ambiguous id: only one may be present per entity",
                    ));
                }
            }
            IsId::Implicit => {
                // no need for an error, rust doesn't let us duplicate field names
                implicit_id_idx = Some(idx);
            }
            IsId::No => {}
        }
    }

    let id_idx = explicit_id_idx.or(implicit_id_idx).ok_or_else(|| {
        Error::new(
            type_span,
            "no id field found; consider marking one with `#[entity(id)]`",
        )
    })?;
    let id_column = fields.swap_remove(id_idx).into_inner().try_into()?;
    let columns = fields
        .into_iter()
        .map(SpannedValue::into_inner)
        .map(TryInto::try_into)
        .collect::<syn::Result<_>>()?;

    Ok((id_column, columns))
}
