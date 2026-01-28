use darling::{
    ast::Data,
    util::{Flag, SpannedValue},
};
use syn::{Ident, Type, Visibility};

/// Parse the outer attributes.
///
/// ```rust,ignore
/// #[derive(Entity)]
/// #[entity(collection_name = "my_collection")]
/// pub struct Entity { ... }
/// ```
#[derive(Default, darling::FromMeta)]
pub(super) struct OuterAttributes {
    pub(super) collection_name: Option<String>,
    pub(super) no_upsert: Flag,
}

/// Parse the field attributes
///
/// ```rust,ignore
/// #[derive(Entity)]
/// pub struct Entity {
///     #[entity(id)]
///     my_id: Vec<u8>,
///     #[entity(hex)]
///     hex_field: Vec<u8>,
///     #[entity(column = "my_column")]
///     rename_this_field: Vec<u8>,
///     #[entity(unencrypted_wasm)]
///     unencrypted_probably_an_index: Vec<u8>,
/// }
/// ```
#[derive(Default, darling::FromMeta)]
pub(super) struct FieldAttributes {
    pub(super) id: Flag,
    pub(super) hex: Flag,
    pub(super) column: Option<String>,
    pub(super) unencrypted_wasm: Flag,
}

impl FieldAttributes {
    pub(super) fn transformation(&self) -> Option<super::FieldTransformation> {
        if self.hex.is_present() {
            Some(super::FieldTransformation::Hex)
        } else {
            None
        }
    }
}

/// Parse the column
#[derive(darling::FromField)]
#[darling(attributes(entity))]
pub(super) struct Column {
    pub(super) ident: Option<Ident>, // but the `supports(struct_named)` ensures it's always Some
    pub(super) ty: Type,
    #[darling(flatten, default)]
    pub(super) field_attrs: FieldAttributes,
}

pub(super) type Columns = Data<(), SpannedValue<Column>>;

/// Representation of a struct annotated with `#[derive(Entity)]`.
#[derive(darling::FromDeriveInput)]
#[darling(attributes(entity), supports(struct_named))]
pub(super) struct Entity {
    /// Visibility of the type the trait is implemented on
    pub(super) vis: Visibility,
    /// Name of the type to implement the trait on
    pub(super) ident: Ident,
    /// Parsed outer attributes of the struct
    #[darling(flatten, default)]
    pub(super) outer_attributes: OuterAttributes,
    /// Columns
    pub(super) data: Columns,
}
