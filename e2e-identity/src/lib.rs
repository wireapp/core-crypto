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

mod e2e_identity;
mod error;
mod types;

pub mod acme;
pub mod pki_env;
pub mod pki_env_hooks;
pub mod x509_check;

pub use acme::{
    AcmeDirectory, RustyAcme, RustyAcmeError, WireIdentity, WireIdentityReader, compute_raw_key_thumbprint,
};
pub use e2e_identity::RustyE2eIdentity;
pub use error::{E2eIdentityError, E2eIdentityResult};
pub use pki_env::{NewCrlDistributionPoints, PkiEnvironmentProvider};
#[cfg(feature = "builder")]
pub use rusty_jwt_tools::prelude::generate_jwk;
pub use rusty_jwt_tools::prelude::{
    ClientId as E2eiClientId, Handle, HashAlgorithm, JwsAlgorithm, RustyJwtError, parse_json_jwk,
};
pub use types::{
    E2eiAcmeAccount, E2eiAcmeAuthorization, E2eiAcmeChallenge, E2eiAcmeFinalize, E2eiAcmeOrder, E2eiNewAcmeOrder,
};
pub use x509_check::IdentityStatus;
