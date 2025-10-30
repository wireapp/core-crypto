/// Result of an order creation.
///
/// - See <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4>
/// - See [core_crypto::e2e_identity::types::E2eiNewAcmeOrder]
#[derive(Debug, uniffi::Record)]
pub struct NewAcmeOrder {
    /// Opaque raw json value
    pub delegate: Vec<u8>,
    /// Authorizations to create with `new_authz_request`
    pub authorizations: Vec<String>,
}

impl From<core_crypto::E2eiNewAcmeOrder> for NewAcmeOrder {
    fn from(new_order: core_crypto::E2eiNewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations,
        }
    }
}

impl From<NewAcmeOrder> for core_crypto::E2eiNewAcmeOrder {
    fn from(new_order: NewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations,
        }
    }
}
