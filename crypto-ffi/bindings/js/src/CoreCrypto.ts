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

export { Ciphersuite } from "./Ciphersuite.js";
export type { ConversationConfiguration } from "./ConversationConfiguration.js";
export type { CoreCryptoRichError } from "./CoreCryptoError.js";
export { CoreCryptoError } from "./CoreCryptoError.js";

export { CoreCryptoContext } from "./CoreCryptoContext.js";

export {
    BuildMetadata,
    WireIdentity,
    X509Identity,
    setLogger,
    CoreCryptoLogLevel,
    setMaxLogLevel,
    buildMetadata,
    version,
    CoreCrypto,
} from "./CoreCryptoInstance.js";
export type {
    CoreCryptoDeferredParams,
    CoreCryptoParams,
    CoreCryptoLogger,
    EpochObserver,
} from "./CoreCryptoInstance.js";

export {
    CredentialType,
    WirePolicy,
    GroupInfoEncryptionType,
    RatchetTreeType,
    DeviceStatus,
    WelcomeBundle,
} from "./CoreCryptoMLS.js";
export type {
    ProposalRef,
    MlsTransportResponse,
    ConversationId,
    ClientId,
    ProposalBundle,
    MlsTransport,
    GroupInfoBundle,
    BufferedDecryptedMessage,
    CommitBundle,
    DecryptedMessage,
} from "./CoreCryptoMLS.js";

export { E2eiEnrollment, E2eiConversationState } from "./CoreCryptoE2EI.js";
export type {
    CRLRegistration,
    AcmeDirectory,
    NewCrlDistributionPoints,
    JsonRawData,
} from "./CoreCryptoE2EI.js";

export type { ProteusAutoPrekeyBundle } from "./CoreCryptoProteus.js";

export { AcmeChallenge, CustomConfiguration } from "./core-crypto-ffi.js";
import initWasm from "./core-crypto-ffi.js";

if (typeof window !== "undefined") {
    // browser context
    await initWasm({});
} else {
    // non-browser context, load WASM module from file
    const fs = await import("fs/promises");
    const path = new URL("core-crypto-ffi_bg.wasm", import.meta.url);
    const file = await fs.open(path);
    const buffer = await file.readFile();
    const module = new WebAssembly.Module(buffer);
    await initWasm({ module_or_path: module });
}
