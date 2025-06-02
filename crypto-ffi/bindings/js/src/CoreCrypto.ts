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

export { Ciphersuite } from "./Ciphersuite";
export type { ConversationConfiguration } from "./ConversationConfiguration";
export { CoreCryptoError, type CoreCryptoRichError } from "./CoreCryptoError";

export { CoreCryptoContext } from "./CoreCryptoContext";

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
} from "./CoreCryptoInstance";
export type {
    CoreCryptoDeferredParams,
    CoreCryptoParams,
    CoreCryptoLogger,
    EpochObserver,
} from "./CoreCryptoInstance";

export {
    CredentialType,
    WirePolicy,
    GroupInfoEncryptionType,
    RatchetTreeType,
    DeviceStatus,
    WelcomeBundle,
} from "./CoreCryptoMLS";
export type {
    ProposalRef,
    MlsTransportResponse,
    ConversationId,
    ClientId,
    MlsTransport,
    GroupInfoBundle,
    BufferedDecryptedMessage,
    CommitBundle,
    DecryptedMessage,
} from "./CoreCryptoMLS";

export { E2eiEnrollment, E2eiConversationState } from "./CoreCryptoE2EI";
export type {
    CRLRegistration,
    AcmeDirectory,
    NewCrlDistributionPoints,
    JsonRawData,
} from "./CoreCryptoE2EI";

export type { ProteusAutoPrekeyBundle } from "./CoreCryptoProteus";

export {
    AcmeChallenge,
    CustomConfiguration,
    DatabaseKey,
    E2eiDumpedPkiEnv,
    migrateDatabaseKeyTypeToBytes,
    NewAcmeAuthz,
    NewAcmeOrder,
} from "./core-crypto-ffi";
import initWasm from "./core-crypto-ffi";

/**
 * Initialises the wasm module necessary for running core crypto.
 *
 * @param location path where the wasm module is located. If omitted the module is assumed be located at the root of the core crypto module.
 */
export async function initWasmModule(location: string | undefined = undefined) {
    if (typeof window !== "undefined") {
        if (typeof location === "string") {
            const path = `${location}core-crypto-ffi_bg.wasm`;
            await initWasm({ module_or_path: path });
        } else {
            await initWasm({});
        }
    } else {
        // non-browser context, load WASM module from file
        const fs = await import("fs/promises");
        const path = new URL("core-crypto-ffi_bg.wasm", import.meta.url);
        const file = await fs.open(path);
        const buffer = await file.readFile();
        const module = new WebAssembly.Module(buffer);
        await initWasm({ module_or_path: module });
    }
}
