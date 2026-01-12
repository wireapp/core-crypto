//! Support for obtaining X.509 certificates that bind keys to Wire users.
//!
//! # Overview
//!
//! On a high level, the process of getting a certificate for a particular Wire client looks like
//! the following:
//!
//! 1. the client requests an [ACME](https://www.rfc-editor.org/rfc/rfc8555.html) server to create a new certificate
//! 2. the ACME server responds with two challenges, [DPoP](#dpop-challenge-wire-dpop-01) and
//!    [OIDC](#oidc-challenge-wire-oidc-01)
//! 3. the client completes the DPoP challenge
//! 4. the client completes the OIDC challenge
//! 5. the ACME server verifies that both challenges are succesfully completed
//! 6. the client generates and submits a CSR (certificate signing request) to the ACME server
//! 7. the ACME server issues a new certificate
//!
//! The client must complete both challenges in order to get a certficate -- completing one
//! challenge is not enough.
//!
//! ```text
//!     ┌───────────────────┐    ┌───────────────────┐     ┌───────────────────┐
//!     │                   │◄───┤                   ├────►│                   │
//!     │    ACME server    │    │    Wire client    │     │    Wire server    │
//!     │                   ├───►│                   │◄────┤                   │
//!     └───────────────────┘    └───────────┬───────┘     └───────────────────┘
//!                                      ▲   │
//!                                      │   │             ┌───────────────────┐
//!                                      │   └────────────►│                   │
//!                                      │                 │     OIDC IdP      │
//!                                      └─────────────────┤                   │
//!                                                        └───────────────────┘
//! ```
//!
//! # Challenges
//!
//! The only ACME server implementation supporting the two custom challenge types necessary for the flow is
//! [step-ca](https://github.com/smallstep/certificates).
//!
//! ## DPoP challenge: `wire-dpop-01`
//!
//! This challenge checks whether the data stored with the Wire server (client ID, user name) matches
//! the data in the device ID that the client submitted when creating the corresponding order.
//!
//! The challenge requires a Wire server that supports the `/clients/{cid}/access-token` endpoint.
//!
//! The flow is roughly as follows:
//!  - the client requests a fresh nonce from the Wire server via the `/clients/{cid}/nonce` endpoint
//!  - the Wire server responds with a nonce
//!  - the client constructs a [DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) token
//!     - the token contains client ID, team and user name
//!     - the token is signed by the clients ACME account key (see [Terminology](https://www.rfc-editor.org/rfc/rfc8555.html#section-3))
//!  - the client sends the DPoP, together with the nonce, to the Wire server, via the `/clients/{cid}/access-token`
//!    endpoint
//!  - the Wire server responds with an access token
//!     - the access token contains the DPoP provided by the client
//!     - the access token is signed by the key whose public part is known to the ACME server
//!  - the client sends the Wire access token to the ACME server
//!  - the ACME server verifies the challenge by
//!     - verifying the outer, Wire access token signature
//!     - verifying the inner, DPoP token signature
//!     - verifying that the DPoP claims match values specified by the challenge
//!
//! [Validation function](https://github.com/smallstep/certificates/blob/2746cd06fb8d68c6720a00e96257038b7e0bbb54/acme/challenge.go#L537)
//!
//! ## OIDC challenge: `wire-oidc-01`
//!
//! This challenge checks whether the data stored with the IdP (name, preferred username) matches
//! the data in the user ID that the client submitted when creating the corresponding order.
//!
//! The challenge requires an OpenID Connect 1.0 conformant provider with
//! support for the [`claims` parameter](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)
//! in the authorization request.
//!
//! **Important**: the IdP (identity provider) has to support specifying the values of the claims
//! requested and those values must be present in the returned ID token. In particular, this
//! mechanism is used by the client to specify values of the `keyauth` and `acme_aud` claims.
//! The client expects the IdP to copy those values to the ID token,
//! e.g.
//! ```text
//!  {
//!   ...
//!   "name": "Alice Smith",
//!   "acme_aud": "https://stepca:32791/acme/wire/challenge/vkdvGckMpDfPFDwOYO6LZhSBx2...
//!   "keyauth": "MXwp2QZezi1xShr3wjNuqKDmmapvtnxv.StoKb1FuB59XWMLjhsdeU94T95R_AoMP3u2g9HscYog",
//!   ...
//!  }
//! ```
//!
//! Strictly speaking, this usage of the `claims` parameter is not according to the OIDC spec as
//! the provider has no way to check that the specified values match.
//!
//! The flow makes use of the [PKCE extension](https://www.rfc-editor.org/rfc/rfc7636) to the
//! [OAuth 2.0 Authorization Code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
//! and looks roughly as follows:
//!  - the client generates a PKCE `(code challenge, code verifier)` pair
//!  - the client makes an authorization request to the user's IdP
//!     - the request makes use of the `claims` parameter to instruct the IdP to include `keyauth` and `acme_aud` claims
//!       with the provided values in the ID token
//!     - the request specifies the `redirect_uri` parameter which is going to be used by the IdP to redirect the user
//!       back after a login
//!     - the request includes the PKCE code challenge value, to be verified later by the IdP when the client requests
//!       an access token
//!  - the user is redirected to the IdP's login page, where authentication is performed
//!  - after a successful authentication, the IdP redirects the user back to the OIDC (in this case Wire) client,
//!    returning the authorization code
//!  - the client uses the authorization code and the PKCE code verifier to make an access token request to the IdP
//!  - the IdP verifies both authorization code and the PKCE code verifier and returns the access token with the ID
//!    token embedded in it; at this point the IdP is no longer needed
//!  - the client extracts the ID token from the access token and sends it to the ACME server
//!  - the ACME server verifies the challenge by
//!     - verifying the ID token signature
//!     - verifying that the `keyauth` value matches the key authorization value for this challenge
//!     - verifying that the `acme_aud` value matches the URL of this challenge
//!     - verifying that the ID token claims match values specified by the challenge (name, Wire handle)
//!
//! [Validation function](https://github.com/smallstep/certificates/blob/2746cd06fb8d68c6720a00e96257038b7e0bbb54/acme/challenge.go#L407)
//!
//! ## References
//!
//! - [RFC7519: JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
//! - [RFC8725: JSON Web Token Best Current Practices](https://www.ietf.org/rfc/rfc8725)
//! - [RFC7636: Proof Key for Code Exchange by OAuth Public Clients](https://www.rfc-editor.org/rfc/rfc7636)
//! - [RFC8555: Automatic Certificate Management Environment (ACME)](https://www.rfc-editor.org/rfc/rfc8555)
//! - [RFC9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
//! - [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
use error::*;
use jwt_simple::prelude::{ES256KeyPair, ES384KeyPair, ES512KeyPair, Ed25519KeyPair, Jwk};
use prelude::*;
use rusty_jwt_tools::{
    jwk::TryIntoJwk,
    jwk_thumbprint::JwkThumbprint,
    prelude::{ClientId, Dpop, Handle, Htm, Pem, RustyJwtTools},
};
use zeroize::Zeroize;

use crate::{
    acme::prelude::{AcmeChallenge, AcmeIdentifier},
    prelude::x509::revocation::PkiEnvironment,
};

pub mod acme;
mod error;
mod types;

pub mod prelude {
    #[cfg(feature = "builder")]
    pub use rusty_jwt_tools::prelude::generate_jwk;
    pub use rusty_jwt_tools::prelude::{
        ClientId as E2eiClientId, Handle, HashAlgorithm, JwsAlgorithm, RustyJwtError, parse_json_jwk,
    };

    pub use super::{
        RustyE2eIdentity,
        error::{E2eIdentityError, E2eIdentityResult},
        types::{
            E2eiAcmeAccount, E2eiAcmeAuthorization, E2eiAcmeChallenge, E2eiAcmeFinalize, E2eiAcmeOrder,
            E2eiNewAcmeOrder,
        },
    };
    pub use crate::acme::prelude::{
        AcmeDirectory, RustyAcme, RustyAcmeError, WireIdentity, WireIdentityReader, compute_raw_key_thumbprint, x509,
        x509::IdentityStatus,
    };
}

pub type Json = serde_json::Value;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RustyE2eIdentity {
    pub sign_alg: JwsAlgorithm,
    pub sign_kp: Pem,
    pub hash_alg: HashAlgorithm,
    pub acme_kp: Pem,
    pub acme_jwk: Jwk,
}

/// Enrollment flow.
impl RustyE2eIdentity {
    /// Builds an instance holding private key material. This instance has to be used in the whole
    /// enrollment process then dropped to clear secret key material.
    ///
    /// # Parameters
    /// * `sign_alg` - Signature algorithm (only Ed25519 for now)
    /// * `raw_sign_key` - Raw signature key as bytes
    pub fn try_new(sign_alg: JwsAlgorithm, mut raw_sign_key: Vec<u8>) -> E2eIdentityResult<Self> {
        let sign_kp = match sign_alg {
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_bytes(&raw_sign_key[..])?.to_pem(),
            JwsAlgorithm::P256 => ES256KeyPair::from_bytes(&raw_sign_key[..])?.to_pem()?,
            JwsAlgorithm::P384 => ES384KeyPair::from_bytes(&raw_sign_key[..])?.to_pem()?,
            JwsAlgorithm::P521 => ES512KeyPair::from_bytes(&raw_sign_key[..])?.to_pem()?,
        };
        let (acme_kp, acme_jwk) = match sign_alg {
            JwsAlgorithm::Ed25519 => {
                let kp = Ed25519KeyPair::generate();
                (kp.to_pem().into(), kp.public_key().try_into_jwk()?)
            }
            JwsAlgorithm::P256 => {
                let kp = ES256KeyPair::generate();
                (kp.to_pem()?.into(), kp.public_key().try_into_jwk()?)
            }
            JwsAlgorithm::P384 => {
                let kp = ES384KeyPair::generate();
                (kp.to_pem()?.into(), kp.public_key().try_into_jwk()?)
            }
            JwsAlgorithm::P521 => {
                let kp = ES512KeyPair::generate();
                (kp.to_pem()?.into(), kp.public_key().try_into_jwk()?)
            }
        };
        // drop the private immediately since it already has been copied
        raw_sign_key.zeroize();
        Ok(Self {
            sign_alg,
            sign_kp: sign_kp.into(),
            hash_alg: HashAlgorithm::from(sign_alg),
            acme_kp,
            acme_jwk,
        })
    }

    /// Parses the response from `GET /acme/{provisioner-name}/directory`.
    /// Use this [AcmeDirectory] in the next step to fetch the first nonce from the acme server. Use
    /// [AcmeDirectory::new_nonce].
    ///
    /// See [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
    ///
    /// # Parameters
    /// * `directory` - http response body
    pub fn acme_directory_response(&self, directory: Json) -> E2eIdentityResult<AcmeDirectory> {
        let directory = RustyAcme::acme_directory_response(directory)?;
        Ok(directory)
    }

    /// For creating a new acme account. This returns a signed JWS-alike request body to send to
    /// `POST /acme/{provisioner-name}/new-account`.
    ///
    /// See [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3).
    ///
    /// # Parameters
    /// * `directory` - you got from [Self::acme_directory_response]
    /// * `previous_nonce` - you got from calling `HEAD {directory.new_nonce}`
    pub fn acme_new_account_request(
        &self,
        directory: &AcmeDirectory,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let acct_req = RustyAcme::new_account_request(directory, self.sign_alg, &self.acme_kp, previous_nonce)?;
        Ok(serde_json::to_value(acct_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/new-account`.
    ///
    /// See [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3).
    ///
    /// # Parameters
    /// * `account` - http response body
    pub fn acme_new_account_response(&self, account: Json) -> E2eIdentityResult<E2eiAcmeAccount> {
        RustyAcme::new_account_response(account)?.try_into()
    }

    /// Creates a new acme order for the handle (userId + display name) and the clientId.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `display_name` - human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// * `domain` - DNS name of owning backend e.g. `example.com`
    /// * `client_id` - client identifier with user b64Url encoded & clientId hex encoded e.g.
    ///   `NDUyMGUyMmY2YjA3NGU3NjkyZjE1NjJjZTAwMmQ2NTQ/6add501bacd1d90e@example.com`
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com`
    /// * `expiry` - x509 generated certificate expiry
    /// * `directory` - you got from [Self::acme_directory_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/new-account`
    #[allow(clippy::too_many_arguments)]
    pub fn acme_new_order_request(
        &self,
        display_name: &str,
        client_id: &str,
        handle: &str,
        expiry: core::time::Duration,
        directory: &AcmeDirectory,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = account.clone().try_into()?;
        let client_id = ClientId::try_from_qualified(client_id)?;
        let order_req = RustyAcme::new_order_request(
            display_name,
            client_id,
            &handle.into(),
            expiry,
            directory,
            &account,
            self.sign_alg,
            &self.acme_kp,
            previous_nonce,
        )?;
        Ok(serde_json::to_value(order_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/new-order`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `new_order` - http response body
    pub fn acme_new_order_response(&self, new_order: Json) -> E2eIdentityResult<E2eiNewAcmeOrder> {
        let new_order = RustyAcme::new_order_response(new_order)?;
        let json_new_order = serde_json::to_vec(&new_order)?.into();
        Ok(E2eiNewAcmeOrder {
            delegate: json_new_order,
            authorizations: new_order.authorizations,
        })
    }

    /// Creates a new authorization request.
    ///
    /// See [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5).
    ///
    /// # Parameters
    /// * `url` - one of the URL in new order's authorizations (from [Self::acme_new_order_response])
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/new-order` (or from the
    ///   previous to this method if you are creating the second authorization)
    pub fn acme_new_authz_request(
        &self,
        url: &url::Url,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = account.clone().try_into()?;
        let authz_req = RustyAcme::new_authz_request(url, &account, self.sign_alg, &self.acme_kp, previous_nonce)?;
        Ok(serde_json::to_value(authz_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/authz/{authz-id}`
    ///
    /// You then have to map the challenge from this authorization object. The `client_id_challenge`
    /// will be the one with the `client_id_host` (you supplied to [Self::acme_new_order_request]) identifier,
    /// the other will be your `handle_challenge`.
    ///
    /// See [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5).
    ///
    /// # Parameters
    /// * `new_authz` - http response body
    pub fn acme_new_authz_response(&self, new_authz: Json) -> E2eIdentityResult<E2eiAcmeAuthorization> {
        let authz = serde_json::from_value(new_authz)?;
        let authz = RustyAcme::new_authz_response(authz)?;

        let [challenge] = authz.challenges;
        Ok(match authz.identifier {
            AcmeIdentifier::WireappUser(_) => {
                let thumbprint = JwkThumbprint::generate(&self.acme_jwk, self.hash_alg)?.kid;
                let oidc_chall_token = &challenge.token;
                let keyauth = format!("{oidc_chall_token}.{thumbprint}");
                E2eiAcmeAuthorization::User {
                    identifier: authz.identifier.to_json()?,
                    challenge: challenge.try_into()?,
                    keyauth,
                }
            }
            AcmeIdentifier::WireappDevice(_) => E2eiAcmeAuthorization::Device {
                identifier: authz.identifier.to_json()?,
                challenge: challenge.try_into()?,
            },
        })
    }

    /// Generates a new client Dpop JWT token. It demonstrates proof of possession of the nonces
    /// (from wire-server & acme server) and will be verified by the acme server when verifying the
    /// challenge (in order to deliver a certificate).
    ///
    /// Then send it to
    /// [`POST /clients/{id}/access-token`](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
    /// on wire-server.
    ///
    /// # Parameters
    /// * `access_token_url` - backend endpoint where this token will be sent. Should be [this one](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
    /// * `client_id` - client identifier with user b64Url encoded & clientId hex encoded e.g.
    ///   `NDUyMGUyMmY2YjA3NGU3NjkyZjE1NjJjZTAwMmQ2NTQ:6add501bacd1d90e@example.com`
    /// * `dpop_challenge` - you found after [Self::acme_new_authz_response]
    /// * `backend_nonce` - you get by calling `GET /clients/token/nonce` on wire-server.
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com` See endpoint [definition](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/get_clients__client__nonce)
    /// * `expiry` - token expiry
    #[allow(clippy::too_many_arguments)]
    pub fn new_dpop_token(
        &self,
        client_id: &str,
        display_name: &str,
        dpop_challenge: &E2eiAcmeChallenge,
        backend_nonce: String,
        handle: &str,
        team: Option<String>,
        expiry: core::time::Duration,
    ) -> E2eIdentityResult<String> {
        let dpop_chall: AcmeChallenge = dpop_challenge.clone().try_into()?;
        let audience = dpop_chall.url;
        let client_id = ClientId::try_from_qualified(client_id)?;
        let handle = Handle::from(handle).try_to_qualified(&client_id.domain)?;
        let dpop = Dpop {
            htm: Htm::Post,
            htu: dpop_challenge.target.clone().into(),
            challenge: dpop_chall.token.into(),
            handle,
            team: team.into(),
            display_name: display_name.to_string(),
            extra_claims: None,
        };
        Ok(RustyJwtTools::generate_dpop_token(
            dpop,
            &client_id,
            backend_nonce.into(),
            audience,
            expiry,
            self.sign_alg,
            &self.acme_kp,
        )?)
    }

    /// Creates a new challenge request.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `access_token` - returned by wire-server from [this endpoint](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
    /// * `dpop_challenge` - you found after [Self::acme_new_authz_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    pub fn acme_dpop_challenge_request(
        &self,
        access_token: String,
        dpop_challenge: &E2eiAcmeChallenge,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = account.clone().try_into()?;
        let dpop_challenge: AcmeChallenge = dpop_challenge.clone().try_into()?;
        let new_challenge_req = RustyAcme::dpop_chall_request(
            access_token,
            dpop_challenge,
            &account,
            self.sign_alg,
            &self.acme_kp,
            previous_nonce,
        )?;
        Ok(serde_json::to_value(new_challenge_req)?)
    }

    /// Creates a new challenge request.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `id_token` - returned by Identity Provider
    /// * `oidc_challenge` - you found after [Self::acme_new_authz_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    pub fn acme_oidc_challenge_request(
        &self,
        id_token: String,
        oidc_challenge: &E2eiAcmeChallenge,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = account.clone().try_into()?;
        let oidc_chall: AcmeChallenge = oidc_challenge.clone().try_into()?;
        let new_challenge_req = RustyAcme::oidc_chall_request(
            id_token,
            oidc_chall,
            &account,
            self.sign_alg,
            &self.acme_kp,
            previous_nonce,
        )?;
        Ok(serde_json::to_value(new_challenge_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}`.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `challenge` - http response body
    pub fn acme_new_challenge_response(&self, challenge: Json) -> E2eIdentityResult<()> {
        let challenge = serde_json::from_value(challenge)?;
        RustyAcme::new_chall_response(challenge)?;
        Ok(())
    }

    /// Verifies that the previous challenge has been completed.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `order_url` - "location" header from http response you got from [Self::acme_new_order_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST
    ///   /acme/{provisioner-name}/challenge/{challenge-id}`
    pub fn acme_check_order_request(
        &self,
        order_url: url::Url,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = account.clone().try_into()?;
        let check_order_req =
            RustyAcme::check_order_request(order_url, &account, self.sign_alg, &self.acme_kp, previous_nonce)?;
        Ok(serde_json::to_value(check_order_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/order/{order-id}`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `order` - http response body
    pub fn acme_check_order_response(&self, order: Json) -> E2eIdentityResult<E2eiAcmeOrder> {
        RustyAcme::check_order_response(order)?.try_into()
    }

    /// Final step before fetching the certificate.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `domains` - domains you want to generate a certificate for e.g. `["wire.com"]`
    /// * `order` - you got from [Self::acme_check_order_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/order/{order-id}`
    pub fn acme_finalize_request(
        &self,
        order: &E2eiAcmeOrder,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let order = order.clone().try_into()?;
        let account = account.clone().try_into()?;
        let finalize_req = RustyAcme::finalize_req(
            &order,
            &account,
            self.sign_alg,
            &self.acme_kp,
            &self.sign_kp,
            previous_nonce,
        )?;
        Ok(serde_json::to_value(finalize_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/order/{order-id}/finalize`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `finalize` - http response body
    pub fn acme_finalize_response(&self, finalize: Json) -> E2eIdentityResult<E2eiAcmeFinalize> {
        RustyAcme::finalize_response(finalize)?.try_into()
    }

    /// Creates a request for finally fetching the x509 certificate.
    ///
    /// See [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2).
    ///
    /// # Parameters
    /// * `domains` - domains you want to generate a certificate for e.g. `["wire.com"]`
    /// * `order` - you got from [Self::acme_check_order_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/order/{order-id}`
    pub fn acme_x509_certificate_request(
        &self,
        finalize: E2eiAcmeFinalize,
        account: E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let finalize = finalize.try_into()?;
        let account = account.try_into()?;
        let certificate_req =
            RustyAcme::certificate_req(finalize, account, self.sign_alg, &self.acme_kp, previous_nonce)?;
        Ok(serde_json::to_value(certificate_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/certificate/{certificate-id}`.
    ///
    /// See [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)
    ///
    /// # Parameters
    /// * `response` - http string response body
    pub fn acme_x509_certificate_response(
        &self,
        response: String,
        order: E2eiAcmeOrder,
        env: Option<&PkiEnvironment>,
    ) -> E2eIdentityResult<Vec<Vec<u8>>> {
        let order = order.try_into()?;
        Ok(RustyAcme::certificate_response(response, order, self.hash_alg, env)?)
    }
}
