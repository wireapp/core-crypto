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

export type { CoreCryptoRichError } from "./CoreCryptoError.js";
export { CoreCryptoError } from "./CoreCryptoError.js";

export { CoreCryptoContext } from "./CoreCryptoContext.js";

export {
    BuildMetadata,
    initLogger,
    setLogger,
    CoreCryptoLogLevel,
    setMaxLogLevel,
    buildMetadata,
    CoreCrypto,
} from "./CoreCryptoInstance.js";
export type {
    CoreCryptoDeferredParams,
    CoreCryptoParams,
    CoreCryptoLogger,
} from "./CoreCryptoInstance.js";

export {
    Ciphersuite,
    CredentialType,
    WirePolicy,
    GroupInfoEncryptionType,
    RatchetTreeType,
    DeviceStatus,
} from "./CoreCryptoMLS.js";
export type {
    ProposalRef,
    MlsTransportResponse,
    ConversationId,
    ClientId,
    WelcomeBundle,
    ProposalBundle,
    MlsTransport,
    GroupInfoBundle,
    BufferedDecryptedMessage,
    CommitBundle,
    ConversationInitBundle,
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

export {
    ConversationConfiguration,
    CustomConfiguration,
} from "./core-crypto-ffi.js";
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
