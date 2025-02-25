use std::collections::HashMap;
use std::str::FromStr;

use itertools::Itertools;
use openmls_traits::OpenMlsCryptoProvider;
use x509_cert::der::pem::LineEnding;

use crate::{
    RecursiveError,
    e2e_identity::{device_status::DeviceStatus, id::WireQualifiedClientId},
    mls::credential::ext::CredentialExt,
    prelude::{ClientId, ConversationId, MlsCentral, MlsConversation, MlsCredentialType, user_id::UserId},
};

use super::{Error, Result};

/// Represents the identity claims identifying a client
/// Those claims are verifiable by any member in the group
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct WireIdentity {
    /// Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov`
    pub client_id: String,
    /// MLS thumbprint
    pub thumbprint: String,
    /// Status of the Credential at the moment T when this object is created
    pub status: DeviceStatus,
    /// Indicates whether the credential is Basic or X509
    pub credential_type: MlsCredentialType,
    /// In case 'credential_type' is [MlsCredentialType::X509] this is populated
    pub x509_identity: Option<X509Identity>,
}

/// Represents the parts of [WireIdentity] that are specific to a X509 certificate (and not a Basic one).
///
/// We don't use an enum here since the sole purpose of this is to be exposed through the FFI (and
/// union types are impossible to carry over the FFI boundary)
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct X509Identity {
    /// user handle e.g. `john_wire`
    pub handle: String,
    /// Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
    pub display_name: String,
    /// DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
    pub domain: String,
    /// X509 certificate identifying this client in the MLS group ; PEM encoded
    pub certificate: String,
    /// X509 certificate serial number
    pub serial_number: String,
    /// X509 certificate not before as Unix timestamp
    pub not_before: u64,
    /// X509 certificate not after as Unix timestamp
    pub not_after: u64,
}

impl<'a> TryFrom<(wire_e2e_identity::prelude::WireIdentity, &'a [u8])> for WireIdentity {
    type Error = Error;

    fn try_from((i, cert): (wire_e2e_identity::prelude::WireIdentity, &'a [u8])) -> Result<Self> {
        use x509_cert::der::Decode as _;
        let document = x509_cert::der::Document::from_der(cert)?;
        let certificate = document.to_pem("CERTIFICATE", LineEnding::LF)?;

        let client_id = WireQualifiedClientId::from_str(&i.client_id)?;

        Ok(Self {
            client_id: client_id.try_into()?,
            status: i.status.into(),
            thumbprint: i.thumbprint,
            credential_type: MlsCredentialType::X509,
            x509_identity: Some(X509Identity {
                handle: i.handle.to_string(),
                display_name: i.display_name,
                domain: i.domain,
                certificate,
                serial_number: i.serial_number,
                not_before: i.not_before,
                not_after: i.not_after,
            }),
        })
    }
}

impl MlsCentral {
    /// From a given conversation, get the identity of the members supplied. Identity is only present for
    /// members with a Certificate Credential (after turning on end-to-end identity).
    /// If no member has a x509 certificate, it will return an empty Vec
    pub async fn get_device_identities(
        &self,
        conversation_id: &ConversationId,
        client_ids: &[ClientId],
    ) -> Result<Vec<WireIdentity>> {
        self.mls_backend
            .authentication_service()
            .refresh_time_of_interest()
            .await;
        let conversation = self
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_conversation("getting conversation by id"))?;
        conversation.get_device_identities(
            client_ids,
            self.mls_backend.authentication_service().borrow().await.as_ref(),
        )
    }

    /// From a given conversation, get the identity of the users (device holders) supplied.
    /// Identity is only present for devices with a Certificate Credential (after turning on end-to-end identity).
    /// If no member has a x509 certificate, it will return an empty Vec.
    ///
    /// Returns a Map with all the identities for a given users. Consumers are then recommended to
    /// reduce those identities to determine the actual status of a user.
    pub async fn get_user_identities(
        &self,
        conversation_id: &ConversationId,
        user_ids: &[String],
    ) -> Result<HashMap<String, Vec<WireIdentity>>> {
        self.mls_backend
            .authentication_service()
            .refresh_time_of_interest()
            .await;
        let conversation = self
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_conversation("getting conversation by id"))?;
        conversation.get_user_identities(
            user_ids,
            self.mls_backend.authentication_service().borrow().await.as_ref(),
        )
    }
}

impl MlsConversation {
    pub(crate) fn get_device_identities(
        &self,
        device_ids: &[ClientId],
        env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
    ) -> Result<Vec<WireIdentity>> {
        if device_ids.is_empty() {
            return Err(Error::EmptyInputIdList);
        }
        self.members_with_key()
            .into_iter()
            .filter(|(id, _)| device_ids.contains(&ClientId::from(id.as_slice())))
            .map(|(_, c)| {
                c.extract_identity(self.ciphersuite(), env)
                    .map_err(RecursiveError::mls_credential("extracting identity"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn get_user_identities(
        &self,
        user_ids: &[String],
        env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
    ) -> Result<HashMap<String, Vec<WireIdentity>>> {
        if user_ids.is_empty() {
            return Err(Error::EmptyInputIdList);
        }
        let user_ids = user_ids.iter().map(|uid| uid.as_bytes()).collect::<Vec<_>>();

        self.members_with_key()
            .iter()
            .filter_map(|(id, c)| UserId::try_from(id.as_slice()).ok().zip(Some(c)))
            .filter(|(uid, _)| user_ids.contains(uid))
            .map(|(uid, c)| {
                let uid = String::try_from(uid).map_err(RecursiveError::mls_client("getting user identities"))?;
                let identity = c
                    .extract_identity(self.ciphersuite(), env)
                    .map_err(RecursiveError::mls_credential("extracting identity"))?;
                Ok((uid, identity))
            })
            .process_results(|iter| iter.into_group_map())
    }
}
