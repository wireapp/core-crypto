// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

export {
    CoreCryptoContext,
    type CredentialFindFilters,
} from "./CoreCryptoContext";

export { CoreCrypto } from "./CoreCryptoInstance";

export {
    BuildMetadata,
    Credential,
    MlsRatchetTreeType as RatchetTreeType,
    MlsGroupInfoEncryptionType as GroupInfoEncryptionType,
    DeviceStatus,
    CredentialType,
    WireIdentity,
    WelcomeBundle,
    X509Identity,
    Ciphersuite,
    CoreCryptoError,
    CoreCryptoError_Tags,
    MlsError,
    MlsError_Tags,
    ProteusError,
    ProteusError_Tags,
    proteusLastResortPrekeyIdFfi as proteusLastResortPrekeyId,
    LoggingError,
    LoggingError_Tags,
    EpochChangedReportingError,
    NewHistoryClientReportingError,
    EpochChangedReportingError_Tags,
    E2eiConversationState,
    ciphersuiteFromU16,
    ciphersuiteDefault,
    ClientId,
    openDatabase,
    Database,
    DatabaseKey,
    type MlsTransportData,
    migrateDatabaseKeyTypeToBytes,
    updateDatabaseKey,
    ExternalSenderKey,
    GroupInfo,
    ConversationId,
    Welcome,
    SecretKey,
    setMaxLogLevel,
    buildMetadata,
    setLogger,
    version,
    type CoreCryptoLogger,
    type EpochObserver,
    type HistoryObserver,
    type CommitBundle,
    type GroupInfoBundle,
    type HistorySecret,
    CredentialRef,
    credentialBasic,
    type DecryptedMessage,
    CoreCryptoLogLevel,
    ProteusAutoPrekeyBundle,
    BufferedDecryptedMessage,
    Keypackage,
    KeypackageRef,
    SignatureScheme,
    PkiEnvironment,
    createPkiEnvironment,
    type PkiEnvironmentHooks,
    PkiEnvironmentHooksError,
    HttpHeader,
    HttpResponse,
    HttpMethod,
    type Timestamp,
    MlsTransportResponse,
    type MlsTransport,
} from "../generated/core_crypto_ffi";

import * as core_crypto_ffi from "../generated/core_crypto_ffi";

/**
 * Initialises the module necessary for running core crypto.
 *
 * @param location path where the wasm module is located. If omitted the module is assumed be located at the root of the core crypto module.
 */
export function initModule() {
    // UBRN initialization
    // Initialize the generated bindings: mostly checksums, but also callbacks.
    // - the boolean flag ensures this loads exactly once, even if the JS code
    //   is reloaded (e.g. during development with metro).
    core_crypto_ffi.default.initialize();
}
