/// For creating a challenge.
///
/// - See <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1>
/// - See [core_crypto::e2e_identity::types::E2eiAcmeChallenge]
#[derive(Debug, Clone, uniffi::Record)]
pub struct AcmeChallenge {
    /// Contains raw JSON data of this challenge. This is parsed by the underlying Rust library hence should not be accessed
    pub delegate: Vec<u8>,
    /// URL of this challenge
    pub url: String,
    /// Non-standard, Wire specific claim. Indicates the consumer from where it should get the challenge proof.
    /// Either from wire-server "/access-token" endpoint in case of a DPoP challenge, or from an OAuth token endpoint for an OIDC challenge
    pub target: String,
}

impl From<core_crypto::E2eiAcmeChallenge> for AcmeChallenge {
    fn from(chall: core_crypto::E2eiAcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
            target: chall.target,
        }
    }
}

impl From<AcmeChallenge> for core_crypto::E2eiAcmeChallenge {
    fn from(chall: AcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
            target: chall.target,
        }
    }
}
