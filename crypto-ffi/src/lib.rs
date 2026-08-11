//! FFI bindings for core-crypto.
//!
//! Actual implementation happens in the `core-crypto` crate. This crate is about setting up all the necessary
//! annotations, wrappers, etc necessary to package those types, items, and methods for FFI via uniffi and wasm-bindgen.

// No public item in this crate should lack documentation.
#![cfg_attr(not(test), deny(missing_docs))]

#[cfg(any(feature = "wasm", feature = "napi"))]
extern crate uniffi_ubrn as uniffi;

uniffi::setup_scaffolding!("core_crypto_ffi");

mod bundles;
mod bytes_wrapper;
#[cfg(feature = "cancellable-transactions")]
mod cancellation;
mod cipher_suite;
mod client_id;
mod core_crypto;
mod core_crypto_context;
mod credential;
mod credential_ref;
mod credential_type;
mod database;
mod decrypted_message;
mod e2ei;
mod ephemeral;
mod error;
mod external_sender;
mod identity;
mod key_package;
mod metadata;
mod pki_env;
mod proteus;
mod signature_scheme;
mod timestamp;

pub use bundles::commit::CommitBundle;
pub use bundles::group_info::GroupInfoBundle;
pub use bundles::proteus_auto_prekey::ProteusAutoPrekeyBundle;
#[cfg(feature = "cancellable-transactions")]
pub use cancellation::CoreCryptoCancellationToken;
pub use cipher_suite::CipherSuite;
pub use cipher_suite::cipher_suite_default;
pub use cipher_suite::cipher_suite_from_u16;
pub use client_id::ClientId;
pub use client_id::DeserializedClientId;
pub use client_id::DeviceId;
pub use client_id::Uuid;
pub use core_crypto::CoreCryptoFfi;
pub use core_crypto::command::CoreCryptoCommand;
#[cfg(not(target_os = "unknown"))]
pub use core_crypto::command::transaction_helper::TransactionHelper;
pub use core_crypto::conversation::ConversationId;
pub use core_crypto::core_crypto_new;
pub(crate) use core_crypto::e2ei::identities::UserIdentities;
pub use core_crypto::epoch_observer::EpochObserver;
pub use core_crypto::logger::CoreCryptoLogLevel;
pub use core_crypto::logger::CoreCryptoLogger;
pub use core_crypto::logger::set_logger;
pub use core_crypto::logger::set_max_log_level;
pub use core_crypto::mls_transport::MlsTransport;
pub use core_crypto::mls_transport::MlsTransportData;
pub use core_crypto_context::CoreCryptoContext;
pub use credential::Credential;
pub use credential_ref::CredentialRef;
pub use credential_type::CredentialType;
pub use database::Database;
pub use database::DatabaseKey;
#[cfg(not(any(feature = "wasm", feature = "napi", target_os = "unknown")))]
pub use database::export_database_copy;
#[cfg(not(any(feature = "wasm", feature = "napi", target_os = "unknown")))]
pub use database::in_memory_database;
pub use database::migrate_database_key_type_to_bytes;
#[cfg(not(any(feature = "wasm", feature = "napi", target_os = "unknown")))]
pub use database::open_database;
pub use decrypted_message::BufferedDecryptedMessage;
pub use decrypted_message::DecryptedMessage;
pub use e2ei::E2eiConversationState;
pub use e2ei::X509CredentialAcquisition;
pub use e2ei::X509CredentialAcquisitionConfiguration;
#[cfg(not(any(feature = "wasm", feature = "napi", target_os = "unknown")))]
pub use e2ei::x509_credential_acquisition_from_credential_ref::x509_credential_acquisition_new_from_credential_ref;
pub use ephemeral::HistorySecret;
pub use ephemeral::core_crypto_history_client;
pub use error::CoreCryptoError;
pub use error::CoreCryptoResult;
pub use error::mls::MlsError;
pub use error::mls_transport::MlsTransportError;
pub use error::mls_transport::MlsTransportResult;
#[cfg(feature = "proteus")]
pub use error::proteus::ProteusError;
pub use external_sender::ExternalSender;
pub use identity::wire::DeviceStatus;
pub use identity::wire::WireIdentity;
pub use identity::x509::X509Identity;
pub use key_package::KeyPackage;
pub use key_package::KeyPackageRef;
pub use metadata::BuildMetadata;
pub use metadata::build_metadata;
pub use metadata::version;
pub use pki_env::HttpHeader;
pub use pki_env::HttpMethod;
pub use pki_env::HttpResponse;
pub use pki_env::PkiEnvironment;
pub use pki_env::PkiEnvironmentHooks;
#[cfg(not(any(feature = "wasm", feature = "napi", target_os = "unknown")))]
pub use pki_env::create_pki_environment;
pub use signature_scheme::SignatureScheme;
pub use timestamp::Timestamp;
