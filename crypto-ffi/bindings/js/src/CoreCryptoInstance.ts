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

import * as CoreCryptoFfiTypes from "./core-crypto-ffi.d.js";
export {
    BuildMetadata,
    WireIdentity,
    X509Identity,
} from "./core-crypto-ffi.d.js";

import {
    CoreCrypto as CoreCryptoFfi,
    CommitBundle as CommitBundleFfi,
    CoreCryptoWasmLogger,
    E2eiDumpedPkiEnv,
    MlsTransportProvider,
    WireIdentity,
} from "./core-crypto-ffi.js";

import { CoreCryptoError } from "./CoreCryptoError.js";
import {
    commitBundleFromFfi,
    mapTransportResponseToFfi,
    CredentialType,
    ConversationId,
    ClientId,
    Ciphersuite,
    MlsTransport,
} from "./CoreCryptoMLS.js";

import { CoreCryptoContext } from "./CoreCryptoContext.js";

import { E2eiConversationState, normalizeEnum } from "./CoreCryptoE2EI.js";

/**
 * Params for CoreCrypto deferred initialization
 * Please note that the `entropySeed` parameter MUST be exactly 32 bytes
 */
export interface CoreCryptoDeferredParams {
    /**
     * Name of the IndexedDB database
     */
    databaseName: string;
    /**
     * Encryption master key
     * This should be appropriately stored in a secure location (i.e. WebCrypto private key storage)
     */
    key: string;
    /**
     * External PRNG entropy pool seed.
     * This **must** be exactly 32 bytes
     */
    entropySeed?: Uint8Array;
    /**
     * .wasm file path, this will be useful in case your bundling system likes to relocate files (i.e. what webpack does)
     */
    wasmFilePath?: string;
}

/**
 * Params for CoreCrypto initialization
 * Please note that the `entropySeed` parameter MUST be exactly 32 bytes
 */
export interface CoreCryptoParams extends CoreCryptoDeferredParams {
    /**
     * MLS Client ID.
     * This should stay consistent as it will be verified against the stored signature & identity to validate the persisted credential
     */
    clientId: ClientId;
    /**
     * All the ciphersuites this MLS client can support
     */
    ciphersuites: Ciphersuite[];
    /**
     * Number of initial KeyPackage to create when initializing the client
     */
    nbKeyPackage?: number;
}

/**
 * Initializes the global logger for Core Crypto and registers the callback.
 *
 * **NOTE:** you must call this after `await CoreCrypto.init(params)` or `await CoreCrypto.deferredInit(params)`.
 *
 * @param logger - the interface to be called when something is going to be logged
 **/
export function setLogger(logger: CoreCryptoLogger, ctx: unknown = null): void {
    const wasmLogger = new CoreCryptoWasmLogger(logger.log, ctx);
    CoreCryptoFfi.set_logger(wasmLogger);
}

/**
 * An interface to register a logger in CoreCrypto
 **/
export interface CoreCryptoLogger {
    /**
     * This method will be called by Core Crypto to log messages. It is up to the implementer to decide how to handle the message and where to actually log it.
     * @param level - the level of the logged message. it will also be present in the json message
     * @param message - log message
     * @param context - additional context captured when the log was made.
     **/
    log: (level: CoreCryptoLogLevel, message: string, context: string) => void;
}

/**
 * Defines the maximum log level for the logs from Core Crypto
 **/
export enum CoreCryptoLogLevel {
    Off = 1,
    Trace = 2,
    Debug = 3,
    Info = 4,
    Warn = 5,
    Error = 6,
}

/**
 * Sets maximum log level for logs forwarded to the logger, defaults to `Warn`.
 *
 * @param level - the max level that should be logged
 */
export function setMaxLogLevel(level: CoreCryptoLogLevel): void {
    CoreCrypto.setMaxLogLevel(level);
}

/**
 * Returns build metadata for the {@link CoreCrypto} libary.
 *
 * @returns varous build metadata for `core-crypto`.
 */
export function buildMetadata(): CoreCryptoFfiTypes.BuildMetadata {
    return CoreCryptoFfi.build_metadata();
}

/**
 * Returns the current version of {@link CoreCrypto}
 *
 * @returns the CoreCrypto version as a string (e.g. "3.1.2")
 */
export function version(): string {
    return CoreCryptoFfi.version();
}

/**
 * Wrapper for the WASM-compiled version of CoreCrypto
 */
export class CoreCrypto {
    /** @hidden */
    #cc: CoreCryptoFfiTypes.CoreCrypto;

    /**
     * Should only be used internally
     */
    inner(): unknown {
        return this.#cc as CoreCryptoFfiTypes.CoreCrypto;
    }

    static setLogger(logger: CoreCryptoWasmLogger) {
        CoreCryptoFfi.set_logger(logger);
    }

    static setMaxLogLevel(level: CoreCryptoLogLevel) {
        CoreCryptoFfi.set_max_log_level(level);
    }

    /**
     * This is your entrypoint to initialize {@link CoreCrypto}!
     *
     * @param params - {@link CoreCryptoParams}
     *
     * @example
     * ## Simple init
     * ```ts
     * const cc = await CoreCrypto.init({ databaseName: "test", key: "test", clientId: "test" });
     * // Do the rest with `cc`
     * ```
     *
     * ## Custom Entropy seed init & wasm file location
     * ```ts
     * // FYI, this is the IETF test vector #1
     * const entropySeed = Uint32Array.from([
     *   0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653,
     *   0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b,
     *   0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8,
     *   0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2,
     * ]);
     *
     * const wasmFilePath = "/long/complicated/path/on/webserver/whatever.wasm";
     *
     * const cc = await CoreCrypto.init({
     *   databaseName: "test",
     *   key: "test",
     *   clientId: "test",
     *   entropySeed,
     *   wasmFilePath,
     * });
     * ````
     */
    static async init({
        databaseName,
        key,
        clientId,
        // @ts-expect-error TS6133: 'wasmFilePath' is declared but its value is never read.
        wasmFilePath, // eslint-disable-line @typescript-eslint/no-unused-vars
        ciphersuites,
        entropySeed,
        nbKeyPackage,
    }: CoreCryptoParams): Promise<CoreCrypto> {
        const cs = ciphersuites.map((cs) => cs.valueOf());
        const cc = await CoreCryptoError.asyncMapErr(
            CoreCryptoFfi._internal_new(
                databaseName,
                key,
                clientId,
                Uint16Array.of(...cs),
                entropySeed,
                nbKeyPackage
            )
        );
        return new this(cc);
    }

    /**
     * Almost identical to {@link CoreCrypto.init} but allows a 2 phase initialization of MLS.
     * First, calling this will set up the keystore and will allow generating proteus prekeys.
     * Then, those keys can be traded for a clientId.
     * Use this clientId to initialize MLS with {@link CoreCryptoContext.mlsInit}.
     * @param params - {@link CoreCryptoDeferredParams}
     */
    static async deferredInit({
        databaseName,
        key,
        entropySeed,
        // @ts-expect-error TS6133: 'wasmFilePath' is declared but its value is never read.
        wasmFilePath, // eslint-disable-line @typescript-eslint/no-unused-vars
    }: CoreCryptoDeferredParams): Promise<CoreCrypto> {
        const cc = await CoreCryptoError.asyncMapErr(
            CoreCryptoFfi.deferred_init(databaseName, key, entropySeed)
        );
        return new this(cc);
    }

    /**
     * Starts a new transaction in Core Crypto. If the callback succeeds, it will be committed,
     * otherwise, every operation performed with the context will be discarded.
     *
     * @param callback - The callback to execute within the transaction
     *
     * @returns the result of the callback will be returned from this call
     */
    async transaction<R>(
        callback: (ctx: CoreCryptoContext) => Promise<R>
    ): Promise<R> {
        let result!: R;
        let error: CoreCryptoError | Error | null = null;
        try {
            await CoreCryptoError.asyncMapErr(
                this.#cc.transaction({
                    execute: async (
                        ctx: CoreCryptoFfiTypes.CoreCryptoContext
                    ) => {
                        try {
                            result = await CoreCryptoError.asyncMapErr(
                                callback(CoreCryptoContext.fromFfiContext(ctx))
                            );
                        } catch (e) {
                            // We want to catch the error before it gets wrapped by core crypto.
                            error = e as Error | CoreCryptoError;
                            // This is to tell core crypto that there was an error inside the transaction.
                            throw error;
                        }
                    },
                })
            );
        } catch (e) {
            // We prefer the closure error if it's available since the transaction will just wrap and re-throw it.
            if (error === null) {
                error = e as Error | CoreCryptoError;
            }
        }
        if (error !== null) {
            throw error;
        }
        return result;
    }

    /** @hidden */
    private constructor(cc: CoreCryptoFfiTypes.CoreCrypto) {
        this.#cc = cc;
    }

    /**
     * If this returns `true` you **cannot** call {@link CoreCrypto.close} as it will produce an error because of the
     * outstanding references that were detected.
     *
     * @returns whether the CoreCrypto instance is locked
     */
    isLocked(): boolean {
        return this.#cc.has_outstanding_refs();
    }

    /**
     * Closes this {@link CoreCrypto} instance and deallocates all loaded resources
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be usable after a call to this method, but there's no way to express this requirement in TypeScript, so you'll get errors instead!
     */
    async close() {
        await CoreCryptoError.asyncMapErr(this.#cc.close());
    }

    /**
     * Registers the transport callbacks for core crypto to give it access to backend endpoints for sending
     * a commit bundle or a message, respectively.
     *
     * @param transportProvider - Any implementor of the {@link MlsTransport} interface
     */
    async provideTransport(
        transportProvider: MlsTransport,
        ctx: unknown = null
    ): Promise<void> {
        try {
            await this.#cc.provide_transport(
                new MlsTransportProvider(
                    async (commitBundle: CommitBundleFfi) => {
                        const result = await transportProvider.sendCommitBundle(
                            commitBundleFromFfi(commitBundle)
                        );
                        return mapTransportResponseToFfi(result);
                    },
                    async (message: Uint8Array) => {
                        const result =
                            await transportProvider.sendMessage(message);
                        return mapTransportResponseToFfi(result);
                    },
                    ctx
                )
            );
        } catch (e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * See {@link CoreCryptoContext.conversationExists}.
     */
    async conversationExists(conversationId: ConversationId): Promise<boolean> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.conversation_exists(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.conversationEpoch}.
     *
     * @returns the epoch of the conversation
     *
     * @example
     * ```ts
     *  const cc = await CoreCrypto.init({ databaseName: "test", key: "test", clientId: "test" });
     *  const encoder = new TextEncoder();
     *  console.log(await cc.conversationEpoch(encoder.encode("my super chat")))
     * ```
     */
    async conversationEpoch(conversationId: ConversationId): Promise<number> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.conversation_epoch(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.conversationCiphersuite}.
     *
     * @returns the ciphersuite of the conversation
     */
    async conversationCiphersuite(
        conversationId: ConversationId
    ): Promise<Ciphersuite> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.conversation_ciphersuite(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.clientPublicKey}.
     *
     * @param ciphersuite - of the signature key to get
     * @param credentialType - of the public key to look for
     * @returns the client's public signature key
     */
    async clientPublicKey(
        ciphersuite: Ciphersuite,
        credentialType: CredentialType
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.client_public_key(ciphersuite, credentialType)
        );
    }

    /**
     * See {@link CoreCryptoContext.exportSecretKey}.
     *
     * @param conversationId - The group's ID
     * @param keyLength - the length of the key to be derived. If the value is higher than the
     * bounds of `u16` or the context hash * 255, an error will be returned
     *
     * @returns A `Uint8Array` representing the derived key
     */
    async exportSecretKey(
        conversationId: ConversationId,
        keyLength: number
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.export_secret_key(conversationId, keyLength)
        );
    }

    /**
     * See {@link CoreCryptoContext.getExternalSender}.
     *
     * @param conversationId - The group's ID
     *
     * @returns A `Uint8Array` representing the external sender raw public key
     */
    async getExternalSender(
        conversationId: ConversationId
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.get_external_sender(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.getClientIds}.
     *
     * @param conversationId - The group's ID
     *
     * @returns A list of clients from the members of the group
     */
    async getClientIds(conversationId: ConversationId): Promise<ClientId[]> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.get_client_ids(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.randomBytes}.
     *
     * @param length - The number of bytes to be returned in the `Uint8Array`
     *
     * @returns A `Uint8Array` buffer that contains `length` cryptographically-secure random bytes
     */
    async randomBytes(length: number): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.random_bytes(length));
    }

    /**
     * Allows to reseed {@link CoreCrypto}'s internal CSPRNG with a new seed.
     *
     * @param seed - **exactly 32** bytes buffer seed
     */
    async reseedRng(seed: Uint8Array): Promise<void> {
        if (seed.length !== 32) {
            throw new Error(
                `The seed length needs to be exactly 32 bytes. ${seed.length} bytes provided.`
            );
        }

        return await CoreCryptoError.asyncMapErr(this.#cc.reseed_rng(seed));
    }

    /**
     * Checks if a session exists
     *
     * @param sessionId - ID of the Proteus session
     *
     * @returns whether the session exists or not
     */
    async proteusSessionExists(sessionId: string): Promise<boolean> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.proteus_session_exists(sessionId)
        );
    }

    /**
     * @returns The last resort PreKey id
     */
    static proteusLastResortPrekeyId(): number {
        return CoreCryptoFfi.proteus_last_resort_prekey_id();
    }

    /**
     * Proteus public key fingerprint
     * It's basically the public key encoded as an hex string
     *
     * @returns Hex-encoded public key string
     */
    async proteusFingerprint(): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.proteus_fingerprint()
        );
    }

    /**
     * Proteus session local fingerprint
     *
     * @param sessionId - ID of the Proteus session
     * @returns Hex-encoded public key string
     */
    async proteusFingerprintLocal(sessionId: string): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.proteus_fingerprint_local(sessionId)
        );
    }

    /**
     * Proteus session remote fingerprint
     *
     * @param sessionId - ID of the Proteus session
     * @returns Hex-encoded public key string
     */
    async proteusFingerprintRemote(sessionId: string): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.proteus_fingerprint_remote(sessionId)
        );
    }

    /**
     * Hex-encoded fingerprint of the given prekey
     *
     * @param prekey - the prekey bundle to get the fingerprint from
     * @returns Hex-encoded public key string
     **/
    static proteusFingerprintPrekeybundle(prekey: Uint8Array): string {
        try {
            return CoreCryptoFfi.proteus_fingerprint_prekeybundle(prekey);
        } catch (e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * See {@link CoreCryptoContext.e2eiDumpPKIEnv}.
     *
     * @returns a struct with different fields representing the PKI environment as PEM strings
     */
    async e2eiDumpPKIEnv(): Promise<E2eiDumpedPkiEnv | undefined> {
        return await this.#cc.e2ei_dump_pki_env();
    }

    /**
     * See {@link CoreCryptoContext.e2eiIsPKIEnvSetup}.
     * @returns whether the E2EI PKI environment is setup (i.e. Root CA, Intermediates, CRLs)
     */
    async e2eiIsPKIEnvSetup(): Promise<boolean> {
        return await this.#cc.e2ei_is_pki_env_setup();
    }

    /**
     * See {@link CoreCryptoContext.e2eiIsEnabled}.
     *
     * @param ciphersuite of the credential to check
     * @returns true if end-to-end identity is enabled for the given ciphersuite
     */
    async e2eiIsEnabled(ciphersuite: Ciphersuite): Promise<boolean> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.e2ei_is_enabled(ciphersuite)
        );
    }

    /**
     * See {@link CoreCryptoContext.getDeviceIdentities}.
     *
     * @param conversationId - identifier of the conversation
     * @param deviceIds - identifiers of the devices
     * @returns identities or if no member has a x509 certificate, it will return an empty List
     */
    async getDeviceIdentities(
        conversationId: ConversationId,
        deviceIds: ClientId[]
    ): Promise<WireIdentity[]> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.get_device_identities(conversationId, deviceIds)
        );
    }

    /**
     * See {@link CoreCryptoContext.getUserIdentities}.
     *
     * @param conversationId - identifier of the conversation
     * @param userIds - user identifiers hyphenated UUIDv4 e.g. 'bd4c7053-1c5a-4020-9559-cd7bf7961954'
     * @returns a Map with all the identities for a given users. Consumers are then recommended to reduce those identities to determine the actual status of a user.
     */
    async getUserIdentities(
        conversationId: ConversationId,
        userIds: string[]
    ): Promise<Map<string, WireIdentity[]>> {
        const map: Map<string, CoreCryptoFfiTypes.WireIdentity[]> =
            await CoreCryptoError.asyncMapErr(
                this.#cc.get_user_identities(conversationId, userIds)
            );

        const mapFixed: Map<string, WireIdentity[]> = new Map();

        for (const [userId, identities] of map) {
            mapFixed.set(
                userId,
                identities.flatMap((identity) => {
                    return identity ? [identity] : [];
                })
            );
        }

        return mapFixed;
    }

    /**
     * See {@link CoreCryptoContext.getCredentialInUse}.
     *
     * @param groupInfo - a TLS encoded GroupInfo fetched from the Delivery Service
     * @param credentialType - kind of Credential to check usage of. Defaults to X509 for now as no other value will give any result.
     * @returns see {@link E2eiConversationState}
     */
    async getCredentialInUse(
        groupInfo: Uint8Array,
        credentialType: CredentialType = CredentialType.X509
    ): Promise<E2eiConversationState> {
        const state = await CoreCryptoError.asyncMapErr(
            this.#cc.get_credential_in_use(groupInfo, credentialType)
        );
        return normalizeEnum(E2eiConversationState, state);
    }
}
