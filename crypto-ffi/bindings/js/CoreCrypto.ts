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


// @ts-ignore
import wasm from "../../../crypto-ffi/Cargo.toml";

import type * as CoreCryptoFfiTypes from "./wasm/core-crypto-ffi";

interface CoreCryptoRichError {
    errorName: string;
    message: string;
    rustStackTrace: string;
    proteusErrorCode: number;
}

/**
 * Error wrapper that takes care of extracting rich error details across the FFI (through JSON parsing)
 *
 * Whenever you're supposed to get this class (that extends `Error`) you might end up with a base `Error`
 * in case the parsing of the message structure fails. This is unlikely but the case is still covered and fall backs automatically.
 * More information will be found in the base `Error.cause` to inform you why the parsing has failed.
 *
 * Please note that in this case the extra properties will not be available.
 */
export class CoreCryptoError extends Error {
    rustStackTrace: string;
    proteusErrorCode: number;

    private constructor(msg: string, richError: CoreCryptoRichError, ...params: any[]) {
        // @ts-ignore
        super(msg, ...params);
        Object.setPrototypeOf(this, new.target.prototype);

        this.name = richError.errorName;
        this.rustStackTrace = richError.rustStackTrace;
        this.proteusErrorCode = richError.proteusErrorCode;
    }

    private static fallback(msg: string, ...params: any[]): Error {
        console.warn(`Cannot build CoreCryptoError, falling back to standard Error! ctx: ${msg}`);
        // @ts-ignore
        return new Error(msg, ...params);
    }

    static build(msg: string, ...params: any[]): CoreCryptoError|Error {
        const parts = msg.split("\n\n");
        if (parts.length < 2) {
            const cause = new Error("CoreCrypto WASM FFI Error doesn't have enough elements to build a rich error");
            return this.fallback(msg, { cause }, ...params);
        }

        const [errMsg, richErrorJSON, ] = parts;
        try {
            const richError: CoreCryptoRichError = JSON.parse(richErrorJSON);
            return new this(errMsg, richError, ...params);
        } catch(cause) {
            return this.fallback(msg, { cause }, ...params);
        }
    }

    static fromStdError(e: Error): CoreCryptoError|Error {
        const opts = {
            // @ts-ignore
            cause: e.cause || undefined,
            stack: e.stack || undefined,
        };

        return this.build(e.message, opts);
    }

    static async asyncMapErr<T>(p: Promise<T>): Promise<T> {
        const mappedErrorPromise = p.catch((e: Error|CoreCryptoError) => {
            if (e instanceof CoreCryptoError) {
                throw e;
            } else {
                throw this.fromStdError(e);
            }
        });

        return await mappedErrorPromise;
    }
}

/**
 * see [core_crypto::prelude::CiphersuiteName]
 */
export enum Ciphersuite {
    /**
     * DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
     */
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    /**
     * DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
     */
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    /**
     * DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
     */
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    /**
     * DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
     */
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    /**
     * DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
     */
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    /**
     * DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
     */
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
    /**
     * DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
     */
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
}

/**
 * Configuration object for new conversations
 */
export interface ConversationConfiguration {
    /**
     * Conversation ciphersuite
     */
    ciphersuite?: Ciphersuite;
    /**
     * List of client IDs that are allowed to be external senders of commits
     */
    externalSenders?: Uint8Array[];
    /**
     * Implementation specific configuration
     */
    custom?: CustomConfiguration;
}

/**
 * see [core_crypto::prelude::MlsWirePolicy]
 */
export enum WirePolicy {
    /**
     * Handshake messages are never encrypted
     */
    Plaintext = 0x0001,
    /**
     * Handshake messages are always encrypted
     */
    Ciphertext = 0x0002,
}

/**
 * Implementation specific configuration object for a conversation
 */
export interface CustomConfiguration {
    /**
     * Duration in seconds after which we will automatically force a self_update commit
     * Note: This isn't currently implemented
     */
    keyRotationSpan?: number;
    /**
     * Defines if handshake messages are encrypted or not
     * Note: Ciphertext is not currently supported by wire-server
     */
    wirePolicy?: WirePolicy;
}

/**
 * Alias for conversation IDs.
 * This is a freeform, uninspected buffer.
 */
export type ConversationId = Uint8Array;

/**
 * Alias for client identifier.
 * This is a freeform, uninspected buffer.
 */
export type ClientId = Uint8Array;

/**
 * Alias for proposal reference. It is a byte array of size 16.
 */
export type ProposalRef = Uint8Array;

/**
 * Data shape for proteusNewPrekeyAuto() call returns.
 */
export interface ProteusAutoPrekeyBundle {
    /**
     * Proteus PreKey id
     *
     * @readonly
     */
    id: number;
    /**
     * CBOR-serialized Proteus PreKeyBundle
     *
     * @readonly
     */
    pkb: Uint8Array;
}

/**
 * Data shape for the returned MLS commit & welcome message tuple upon adding clients to a conversation
 */
export interface MemberAddedMessages {
    /**
     * TLS-serialized MLS Commit that needs to be fanned out to other (existing) members of the conversation
     *
     * @readonly
     */
    commit: Uint8Array;
    /**
     * TLS-serialized MLS Welcome message that needs to be fanned out to the clients newly added to the conversation
     *
     * @readonly
     */
    welcome: Uint8Array;
    /**
     * MLS PublicGroupState (GroupInfo in draft-15) which is required for joining a group by external commit
     *
     * @readonly
     */
    publicGroupState: PublicGroupStateBundle;
}

/**
 * Data shape for a MLS generic commit + optional bundle (aka stapled commit & welcome)
 */
export interface CommitBundle {
    /**
     * TLS-serialized MLS Commit that needs to be fanned out to other (existing) members of the conversation
     *
     * @readonly
     */
    commit: Uint8Array;
    /**
     * Optional TLS-serialized MLS Welcome message that needs to be fanned out to the clients newly added to the conversation
     *
     * @readonly
     */
    welcome?: Uint8Array;
    /**
     * MLS PublicGroupState (GroupInfo in draft-15) which is required for joining a group by external commit
     *
     * @readonly
     */
    publicGroupState: PublicGroupStateBundle;
}

/**
 * Wraps a PublicGroupState in order to efficiently upload it to the Delivery Service.
 * This is not part of MLS protocol but parts might be standardized at some point.
 */
export interface PublicGroupStateBundle {
    /**
     * see {@link PublicGroupStateEncryptionType}
     */
    encryptionType: PublicGroupStateEncryptionType,
    /**
     * see {@link RatchetTreeType}
     */
    ratchetTreeType: RatchetTreeType,
    /**
     * TLS-serialized PublicGroupState
     */
    payload: Uint8Array,
}

/**
 * Informs whether the PublicGroupState is confidential
 * see [core_crypto::mls::conversation::public_group_state::PublicGroupStateEncryptionType]
 */
export enum PublicGroupStateEncryptionType {
    /**
     * Unencrypted
     */
    Plaintext = 0x01,
    /**
     * Encrypted in a JWE (not yet implemented)
     */
    JweEncrypted = 0x02,
}

/**
 * Represents different ways of carrying the Ratchet Tree with some optimizations to save some space
 * see [core_crypto::mls::conversation::public_group_state::RatchetTreeType]
 */
export enum RatchetTreeType {
    /**
     * Complete PublicGroupState
     */
    Full = 0x01,
    /**
     * Contains the difference since previous epoch (not yet implemented)
     */
    Delta = 0x02,
    /**
     * To define (not yet implemented)
     */
    ByRef = 0x03,
}

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
}

/**
 * Data shape for adding clients to a conversation
 */
export interface Invitee {
    /**
     * Client ID as a byte array
     */
    id: ClientId;
    /**
     * MLS KeyPackage belonging to the aforementioned client
     */
    kp: Uint8Array;
}

export interface ConversationInitBundle {
    /**
     * Conversation ID of the conversation created
     *
     * @readonly
     */
    conversationId: ConversationId;
    /**
     * TLS-serialized MLS External Commit that needs to be fanned out
     *
     * @readonly
     */
    commit: Uint8Array;
    /**
     * MLS Public Group State (aka Group Info) which becomes valid when the external commit is accepted by the Delivery Service
     * with {@link CoreCrypto.mergePendingGroupFromExternalCommit}
     *
     * @readonly
     */
    publicGroupState: PublicGroupStateBundle;
}

/**
 * This is a wrapper for all the possible outcomes you can get after decrypting a message
 */
export interface DecryptedMessage {
    /**
     * Raw decrypted application message, if the decrypted MLS message is an application message
     */
    message?: Uint8Array;
    /**
     * Only when decrypted message is a commit, CoreCrypto will renew local proposal which could not make it in the commit.
     * This will contain either:
     *   * local pending proposal not in the accepted commit
     *   * If there is a pending commit, its proposals which are not in the accepted commit
     */
    proposals: ProposalBundle[];
    /**
     * It is set to false if ingesting this MLS message has resulted in the client being removed from the group (i.e. a Remove commit)
     */
    isActive: boolean;
    /**
     * Commit delay hint (in milliseconds) to prevent clients from hammering the server with epoch changes
     */
    commitDelay?: number;
    /**
     * Client identifier of the sender of the message being decrypted. Only present for application messages.
     */
    senderClientId?: ClientId;
    /**
     * true when the decrypted message resulted in an epoch change i.e. it was a commit
     */
    hasEpochChanged: boolean;
}

/**
 * Returned by all methods creating proposals. Contains a proposal message and an identifier to roll back the proposal
 */
export interface ProposalBundle {
    /**
     * TLS-serialized MLS proposal that needs to be fanned out to other (existing) members of the conversation
     *
     * @readonly
     */
    proposal: Uint8Array;
    /**
     * Unique identifier of a proposal. Use this in {@link CoreCrypto.clearPendingProposal} to roll back (delete) the proposal
     *
     * @readonly
     */
    proposalRef: ProposalRef;
}

/**
 * MLS Proposal type
 */
export enum ProposalType {
    /**
     * This allows to propose the addition of other clients to the MLS group/conversation
     */
    Add,
    /**
     * This allows to propose the removal of clients from the MLS group/conversation
     */
    Remove,
    /**
     * This allows to propose to update the client keying material (i.e. keypackage rotation) and the group root key
     */
    Update,
}

/**
 * Common arguments for proposals
 */
export interface ProposalArgs {
    /**
     * Conversation ID that is targeted by the proposal
     */
    conversationId: ConversationId;
}

/**
 * Arguments for a proposal of type `Add`
 */
export interface AddProposalArgs extends ProposalArgs {
    /**
     * TLS-serialized MLS KeyPackage to be added
     */
    kp: Uint8Array;
}

/**
 * Arguments for a proposal of type `Remove`
 */
export interface RemoveProposalArgs extends ProposalArgs {
    /**
     * Client ID to be removed from the conversation
     */
    clientId: ClientId;
}

/**
 * MLS External Proposal type
 */
export enum ExternalProposalType {
    /**
     * This allows to propose the addition of other clients to the MLS group/conversation
     */
    Add,
    /**
     * This allows to propose the removal of clients from the MLS group/conversation
     */
    Remove,
}

export interface ExternalProposalArgs {
    /**
     * Conversation ID that is targeted by the external proposal
     */
    conversationId: ConversationId;
    /**
     * MLS Group epoch for the external proposal.
     * This needs to be the current epoch of the group or this proposal **will** be rejected
     */
    epoch: number;
}

export interface ExternalRemoveProposalArgs extends ExternalProposalArgs {
    /**
     * KeyPackageRef of the client that needs to be removed in the proposal
     */
    keyPackageRef: Uint8Array;
}

export interface CoreCryptoCallbacks {
    /**
     * This callback is called by CoreCrypto to know whether a given clientId is authorized to "write"
     * in the given conversationId. Think of it as a "isAdmin" callback conceptually
     *
     * This callback exists because there are many business cases where CoreCrypto doesn't have enough knowledge
     * (such as what can exist on a backend) to inform the decision
     *
     * @param conversationId - id of the group/conversation
     * @param clientId - id of the client performing an operation requiring authorization
     * @returns whether the user is authorized by the logic layer to perform the operation
     */
    authorize: (conversationId: Uint8Array, clientId: Uint8Array) => Promise<boolean>;

    /**
     * A mix between {@link authorize} and {@link clientIsExistingGroupUser}. We currently use this callback to verify
     * external commits to join a group ; in such case, the client has to:
     * * first, belong to a user which is already in the MLS group (similar to {@link clientIsExistingGroupUser})
     * * then, this user should be authorized to "write" in the given conversation (similar to {@link authorize})
     *
     * @param conversationId - id of the group/conversation
     * @param externalClientId - id of the client performing an operation requiring authorization
     * @param existingClients - all the clients currently within the MLS group
     * @returns true if the external client is authorized to write to the conversation
     */
    userAuthorize: (conversationId: Uint8Array, externalClientId: Uint8Array, existingClients: Uint8Array[]) => Promise<boolean>;

    /**
     * Callback to ensure that the given `clientId` belongs to one of the provided `existingClients`
     * This basically allows to defer the client ID parsing logic to the caller - because CoreCrypto is oblivious to such things
     *
     * @param conversationId - id of the group/conversation
     * @param clientId - id of a client
     * @param existingClients - all the clients currently within the MLS group
     */
    clientIsExistingGroupUser: (conversationId: Uint8Array, clientId: Uint8Array, existingClients: Uint8Array[], parent_conversation_clients?: Uint8Array[]) => Promise<boolean>;
}

/**
 * Wrapper for the WASM-compiled version of CoreCrypto
 */
export class CoreCrypto {
    /** @hidden */
    static #module: typeof CoreCryptoFfiTypes;
    /** @hidden */
    #cc: CoreCryptoFfiTypes.CoreCrypto;

    /** @hidden */
    static #assertModuleLoaded() {
        if (!this.#module) {
            throw new Error(
                "Internal module hasn't been initialized. Please use `await CoreCrypto.init(params)` or `await CoreCrypto.deferredInit(params)` !"
            );
        }
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
    static async init({ databaseName, key, clientId, wasmFilePath, entropySeed }: CoreCryptoParams): Promise<CoreCrypto> {
        if (!this.#module) {
            const wasmImportArgs = wasmFilePath ? {importHook: () => wasmFilePath} : undefined;
            const exports = (await wasm(wasmImportArgs)) as typeof CoreCryptoFfiTypes;
            this.#module = exports;
        }
        const cc = await CoreCryptoError.asyncMapErr(this.#module.CoreCrypto._internal_new(databaseName, key, clientId, entropySeed));
        return new this(cc);
    }

    /**
     * Almost identical to {@link CoreCrypto.init} but allows a 2 phase initialization of MLS.
     * First, calling this will set up the keystore and will allow generating proteus prekeys.
     * Then, those keys can be traded for a clientId.
     * Use this clientId to initialize MLS with {@link CoreCrypto.mlsInit}.
     * @param params - {@link CoreCryptoDeferredParams}
     */
    static async deferredInit({ databaseName, key, entropySeed, wasmFilePath }: CoreCryptoDeferredParams): Promise<CoreCrypto> {
        if (!this.#module) {
            const wasmImportArgs = wasmFilePath ? {importHook: () => wasmFilePath} : undefined;
            const exports = (await wasm(wasmImportArgs)) as typeof CoreCryptoFfiTypes;
            this.#module = exports;
        }
        const cc = await CoreCryptoError.asyncMapErr(this.#module.CoreCrypto.deferred_init(databaseName, key, entropySeed));
        return new this(cc);
    }

    /**
     * Use this after {@link CoreCrypto.deferredInit} when you have a clientId. It initializes MLS.
     *
     * @param clientId - {@link CoreCryptoParams#clientId} but required
     */
    async mlsInit(clientId: ClientId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.mls_init(clientId));
    }

    /**
     * Generates a MLS KeyPair/CredentialBundle with a temporary, random client ID.
     * This method is designed to be used in conjunction with {@link CoreCrypto.mlsInitWithClientID} and represents the first step in this process
     *
     * @returns This returns the TLS-serialized identity key (i.e. the signature keypair's public key)
     */
    async mlsGenerateKeypair(): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.mls_generate_keypair());
    }

    /**
     * Updates the current temporary Client ID with the newly provided one. This is the second step in the externally-generated clients process
     *
     * Important: This is designed to be called after {@link CoreCrypto.mlsGenerateKeyPair}
     *
     * @param clientId - The newly-allocated client ID by the MLS Authentication Service
     * @param signaturePublicKey - The public key you were given at the first step; This is for authentication purposes
     */
    async mlsInitWithClientId(clientId: ClientId, signaturePublicKey: Uint8Array): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.mls_init_with_client_id(clientId, signaturePublicKey));
    }

    /** @hidden */
    private constructor(cc: CoreCryptoFfiTypes.CoreCrypto) {
        this.#cc = cc;
    }

    /**
     * Wipes the {@link CoreCrypto} backing storage (i.e. {@link https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API | IndexedDB} database)
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be useable after a call to this method, but there's no way to express this requirement in TypeScript so you'll get errors instead!
     */
    async wipe() {
        await CoreCryptoError.asyncMapErr(this.#cc.wipe());
    }

    /**
     * Closes this {@link CoreCrypto} instance and deallocates all loaded resources
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be useable after a call to this method, but there's no way to express this requirement in TypeScript so you'll get errors instead!
     */
    async close() {
        await CoreCryptoError.asyncMapErr(this.#cc.close());
    }

    /**
     * Registers the callbacks for CoreCrypto to use in order to gain additional information
     *
     * @param callbacks - Any interface following the {@link CoreCryptoCallbacks} interface
     */
    async registerCallbacks(callbacks: CoreCryptoCallbacks, ctx: any = null): Promise<void> {
        try {
            const wasmCallbacks = new CoreCrypto.#module.CoreCryptoWasmCallbacks(
                callbacks.authorize,
                callbacks.userAuthorize,
                callbacks.clientIsExistingGroupUser,
                ctx,
            );
            await this.#cc.set_callbacks(wasmCallbacks);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Checks if the Client is member of a given conversation and if the MLS Group is loaded up
     *
     * @returns Whether the given conversation ID exists
     *
     * @example
     * ```ts
     *  const cc = await CoreCrypto.init({ databaseName: "test", key: "test", clientId: "test" });
     *  const encoder = new TextEncoder();
     *  if (await cc.conversationExists(encoder.encode("my super chat"))) {
     *    // Do something
     *  } else {
     *    // Do something else
     *  }
     * ```
     */
    async conversationExists(conversationId: ConversationId): Promise<boolean> {
        return await CoreCryptoError.asyncMapErr(this.#cc.conversation_exists(conversationId));
    }

    /**
    * Marks a conversation as child of another one
    * This will mostly affect the behavior of the callbacks (the parentConversationClients parameter will be filled)
    *
    * @param childId - conversation identifier of the child conversation
    * @param parentId - conversation identifier of the parent conversation
    */
    async markConversationAsChildOf(childId: ConversationId, parentId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.mark_conversation_as_child_of(childId, parentId));
    }

    /**
     * Returns the current epoch of a conversation
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
        return await CoreCryptoError.asyncMapErr(this.#cc.conversation_epoch(conversationId));
    }

    /**
     * Wipes and destroys the local storage of a given conversation / MLS group
     *
     * @param conversationId - The ID of the conversation to remove
     */
    async wipeConversation(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.wipe_conversation(conversationId));
    }

    /**
     * Creates a new conversation with the current client being the sole member
     * You will want to use {@link CoreCrypto.addClientsToConversation} afterwards to add clients to this conversation
     *
     * @param conversationId - The conversation ID; You can either make them random or let the backend attribute MLS group IDs
     * @param configuration - configuration of the MLS group
     * @param configuration.ciphersuite - The {@link Ciphersuite} that is chosen to be the group's
     * @param configuration.externalSenders - Array of Client IDs that are qualified as external senders within the group
     * @param configuration.custom - {@link CustomConfiguration}
     */
    async createConversation(
        conversationId: ConversationId,
        configuration: ConversationConfiguration = {}
    ) {
        try {
            const {ciphersuite, externalSenders, custom = {}} = configuration || {};
            const config = new CoreCrypto.#module.ConversationConfiguration(
                ciphersuite,
                externalSenders,
                custom?.keyRotationSpan,
            );
            const ret = await CoreCryptoError.asyncMapErr(this.#cc.create_conversation(conversationId, config));
            return ret;
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Decrypts a message for a given conversation
     *
     * @param conversationId - The ID of the conversation
     * @param payload - The encrypted message buffer
     *
     * @returns a {@link DecryptedMessage}. Note that {@link DecryptedMessage#message} is `undefined` when the encrypted payload contains a system message such a proposal or commit
     */
    async decryptMessage(conversationId: ConversationId, payload: Uint8Array): Promise<DecryptedMessage> {
        if (!payload?.length) {
            throw new Error("decryptMessage payload is empty or null");
        }

        try {
            const ffiDecryptedMessage: CoreCryptoFfiTypes.DecryptedMessage = await CoreCryptoError.asyncMapErr(this.#cc.decrypt_message(
                conversationId,
                payload
            ));

            const ffiCommitDelay = ffiDecryptedMessage.commit_delay;

            let commitDelay = undefined;
            if (typeof ffiCommitDelay === "number" && ffiCommitDelay >= 0) {
                commitDelay = ffiCommitDelay * 1000;
            }

            const ret: DecryptedMessage = {
                message: ffiDecryptedMessage.message,
                proposals: ffiDecryptedMessage.proposals,
                isActive: ffiDecryptedMessage.is_active,
                senderClientId: ffiDecryptedMessage.sender_client_id,
                commitDelay,
                hasEpochChanged: ffiDecryptedMessage.has_epoch_changed,
            };

            return ret;
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Encrypts a message for a given conversation
     *
     * @param conversationId - The ID of the conversation
     * @param message - The plaintext message to encrypt
     *
     * @returns The encrypted payload for the given group. This needs to be fanned out to the other members of the group.
     */
    async encryptMessage(conversationId: ConversationId, message: Uint8Array): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.encrypt_message(
            conversationId,
            message
        ));
    }

    /**
     * Ingest a TLS-serialized MLS welcome message to join an existing MLS group
     *
     * @param welcomeMessage - TLS-serialized MLS Welcome message
     * @param configuration - configuration of the MLS group
     * @returns The conversation ID of the newly joined group. You can use the same ID to decrypt/encrypt messages
     */
    async processWelcomeMessage(welcomeMessage: Uint8Array, configuration: CustomConfiguration = {}): Promise<ConversationId> {
        try {
            const {keyRotationSpan, wirePolicy} = configuration || {};
            const config = new CoreCrypto.#module.CustomConfiguration(keyRotationSpan, wirePolicy);
            return await CoreCryptoError.asyncMapErr(this.#cc.process_welcome_message(welcomeMessage, config));
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * @returns The client's public key
     */
    async clientPublicKey(): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.client_public_key());
    }

    /**
     * @returns The amount of valid, non-expired KeyPackages that are persisted in the backing storage
     */
    async clientValidKeypackagesCount(): Promise<number> {
        return await CoreCryptoError.asyncMapErr(this.#cc.client_valid_keypackages_count());
    }

    /**
     * Fetches a requested amount of keypackages
     *
     * @param amountRequested - The amount of keypackages requested
     * @returns An array of length `amountRequested` containing TLS-serialized KeyPackages
     */
    async clientKeypackages(amountRequested: number): Promise<Array<Uint8Array>> {
        return await CoreCryptoError.asyncMapErr(this.#cc.client_keypackages(amountRequested));
    }

    /**
     * Adds new clients to a conversation, assuming the current client has the right to add new clients to the conversation.
     *
     * **CAUTION**: {@link CoreCrypto.commitAccepted} **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
     * '200 OK' to the {@link CommitBundle} upload. It will "merge" the commit locally i.e. increment the local group
     * epoch, use new encryption secrets etc...
     *
     * @param conversationId - The ID of the conversation
     * @param clients - Array of {@link Invitee} (which are Client ID / KeyPackage pairs)
     *
     * @returns A {@link CommitBundle}
     */
    async addClientsToConversation(
        conversationId: ConversationId,
        clients: Invitee[]
    ): Promise<MemberAddedMessages> {
        try {
            const ffiClients = clients.map(
                (invitee) => new CoreCrypto.#module.Invitee(invitee.id, invitee.kp)
            );

            const ffiRet: CoreCryptoFfiTypes.MemberAddedMessages = await CoreCryptoError.asyncMapErr(this.#cc.add_clients_to_conversation(
                conversationId,
                ffiClients
            ));

            ffiClients.forEach(c => c.free());

            const pgs = ffiRet.public_group_state;

            const ret: MemberAddedMessages = {
                welcome: ffiRet.welcome,
                commit: ffiRet.commit,
                publicGroupState: {
                    encryptionType: pgs.encryption_type,
                    ratchetTreeType: pgs.ratchet_tree_type,
                    payload: pgs.payload
                },
            };

            return ret;
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Removes the provided clients from a conversation; Assuming those clients exist and the current client is allowed
     * to do so, otherwise this operation does nothing.
     *
     * **CAUTION**: {@link CoreCrypto.commitAccepted} **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
     * '200 OK' to the {@link CommitBundle} upload. It will "merge" the commit locally i.e. increment the local group
     * epoch, use new encryption secrets etc...
     *
     * @param conversationId - The ID of the conversation
     * @param clientIds - Array of Client IDs to remove.
     *
     * @returns A {@link CommitBundle}
     */
    async removeClientsFromConversation(
        conversationId: ConversationId,
        clientIds: ClientId[]
    ): Promise<CommitBundle> {
        try {
            const ffiRet: CoreCryptoFfiTypes.CommitBundle = await CoreCryptoError.asyncMapErr(this.#cc.remove_clients_from_conversation(
                conversationId,
                clientIds
            ));

            const pgs = ffiRet.public_group_state;

            const ret: CommitBundle = {
                welcome: ffiRet.welcome,
                commit: ffiRet.commit,
                publicGroupState: {
                    encryptionType: pgs.encryption_type,
                    ratchetTreeType: pgs.ratchet_tree_type,
                    payload: pgs.payload
                },
            };

            return ret;
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Creates an update commit which forces every client to update their keypackages in the conversation
     *
     * **CAUTION**: {@link CoreCrypto.commitAccepted} **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
     * '200 OK' to the {@link CommitBundle} upload. It will "merge" the commit locally i.e. increment the local group
     * epoch, use new encryption secrets etc...
     *
     * @param conversationId - The ID of the conversation
     *
     * @returns A {@link CommitBundle}
     */
    async updateKeyingMaterial(conversationId: ConversationId): Promise<CommitBundle> {
        try {
            const ffiRet: CoreCryptoFfiTypes.CommitBundle = await CoreCryptoError.asyncMapErr(this.#cc.update_keying_material(
                conversationId
            ));

            const pgs = ffiRet.public_group_state;

            const ret: CommitBundle = {
                welcome: ffiRet.welcome,
                commit: ffiRet.commit,
                publicGroupState: {
                    encryptionType: pgs.encryption_type,
                    ratchetTreeType: pgs.ratchet_tree_type,
                    payload: pgs.payload
                },
            };

            return ret;
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Commits the local pending proposals and returns the {@link CommitBundle} object containing what can result from this operation.
     *
     * **CAUTION**: {@link CoreCrypto.commitAccepted} **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
     * '200 OK' to the {@link CommitBundle} upload. It will "merge" the commit locally i.e. increment the local group
     * epoch, use new encryption secrets etc...
     *
     * @param conversationId - The ID of the conversation
     *
     * @returns A {@link CommitBundle} or `undefined` when there was no pending proposal to commit
     */
    async commitPendingProposals(conversationId: ConversationId): Promise<CommitBundle | undefined> {
        try {
            const ffiCommitBundle: CoreCryptoFfiTypes.CommitBundle | undefined = await CoreCryptoError.asyncMapErr(this.#cc.commit_pending_proposals(
                conversationId
            ));

            if (!ffiCommitBundle) {
                return undefined;
            }

            const pgs = ffiCommitBundle.public_group_state;

            return {
                welcome: ffiCommitBundle.welcome,
                commit: ffiCommitBundle.commit,
                publicGroupState: {
                    encryptionType: pgs.encryption_type,
                    ratchetTreeType: pgs.ratchet_tree_type,
                    payload: pgs.payload
                },
            };
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Creates a new proposal for the provided Conversation ID
     *
     * @param proposalType - The type of proposal, see {@link ProposalType}
     * @param args - The arguments of the proposal, see {@link ProposalArgs}, {@link AddProposalArgs} or {@link RemoveProposalArgs}
     *
     * @returns A {@link ProposalBundle} containing the Proposal and its reference in order to roll it back if necessary
     */
    async newProposal(
        proposalType: ProposalType,
        args: ProposalArgs | AddProposalArgs | RemoveProposalArgs
    ): Promise<ProposalBundle> {
        switch (proposalType) {
            case ProposalType.Add: {
                if (!(args as AddProposalArgs).kp) {
                    throw new Error("kp is not contained in the proposal arguments");
                }
                return await CoreCryptoError.asyncMapErr(this.#cc.new_add_proposal(
                    args.conversationId,
                    (args as AddProposalArgs).kp
                ));
            }
            case ProposalType.Remove: {
                if (!(args as RemoveProposalArgs).clientId) {
                    throw new Error(
                        "clientId is not contained in the proposal arguments"
                    );
                }
                return await CoreCryptoError.asyncMapErr(this.#cc.new_remove_proposal(
                    args.conversationId,
                    (args as RemoveProposalArgs).clientId
                ));
            }
            case ProposalType.Update: {
                return await CoreCryptoError.asyncMapErr(this.#cc.new_update_proposal(
                    args.conversationId
                ));
            }
            default:
                throw new Error("Invalid proposal type!");
        }
    }

    async newExternalProposal(
        externalProposalType: ExternalProposalType,
        args: ExternalProposalArgs | ExternalRemoveProposalArgs
    ): Promise<Uint8Array> {
        switch (externalProposalType) {
            case ExternalProposalType.Add: {
                return await CoreCryptoError.asyncMapErr(this.#cc.new_external_add_proposal(args.conversationId, args.epoch));
            }
            case ExternalProposalType.Remove: {
                if (!(args as ExternalRemoveProposalArgs).keyPackageRef) {
                    throw new Error("keyPackageRef is not contained in the external proposal arguments");
                }

                return await CoreCryptoError.asyncMapErr(this.#cc.new_external_remove_proposal(
                    args.conversationId,
                    args.epoch,
                    (args as ExternalRemoveProposalArgs).keyPackageRef
                ));
            }
            default:
                throw new Error("Invalid external proposal type!");
        }
    }

    /**
     * Exports public group state for use in external commits
     *
     * @param conversationId - MLS Conversation ID
     * @returns TLS-serialized MLS public group state
     */
    async exportGroupState(conversationId: ConversationId): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.export_group_state(conversationId));
    }

    /**
     * Allows to create an external commit to "apply" to join a group through its public group state.
     *
     * If the Delivery Service accepts the external commit, you have to {@link CoreCrypto.mergePendingGroupFromExternalCommit}
     * in order to get back a functional MLS group. On the opposite, if it rejects it, you can either retry by just
     * calling again {@link CoreCrypto.joinByExternalCommit}, no need to {@link CoreCrypto.clearPendingGroupFromExternalCommit}.
     * If you want to abort the operation (too many retries or the user decided to abort), you can use
     * {@link CoreCrypto.clearPendingGroupFromExternalCommit} in order not to bloat the user's storage but nothing
     * bad can happen if you forget to except some storage space wasted.
     *
     * @param publicGroupState - a TLS encoded PublicGroupState fetched from the Delivery Service
     * @param configuration - configuration of the MLS group
     * @returns see {@link ConversationInitBundle}
     */
    async joinByExternalCommit(publicGroupState: Uint8Array, configuration: CustomConfiguration = {}): Promise<ConversationInitBundle> {
        try {
            const {keyRotationSpan, wirePolicy} = configuration || {};
            const config = new CoreCrypto.#module.CustomConfiguration(keyRotationSpan, wirePolicy);
            const ffiInitMessage: CoreCryptoFfiTypes.ConversationInitBundle = await CoreCryptoError.asyncMapErr(this.#cc.join_by_external_commit(publicGroupState, config));

            const pgs = ffiInitMessage.public_group_state;

            const ret: ConversationInitBundle = {
                conversationId: ffiInitMessage.conversation_id,
                commit: ffiInitMessage.commit,
                publicGroupState: {
                    encryptionType: pgs.encryption_type,
                    ratchetTreeType: pgs.ratchet_tree_type,
                    payload: pgs.payload
                },
            };

            return ret;
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * This merges the commit generated by {@link CoreCrypto.joinByExternalCommit}, persists the group permanently
     * and deletes the temporary one. This step makes the group operational and ready to encrypt/decrypt message
     *
     * @param conversationId - The ID of the conversation
     */
    async mergePendingGroupFromExternalCommit(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.merge_pending_group_from_external_commit(conversationId));
    }

    /**
     * In case the external commit generated by {@link CoreCrypto.joinByExternalCommit} is rejected by the Delivery Service, and we
     * want to abort this external commit once for all, we can wipe out the pending group from the keystore in order
     * not to waste space
     *
     * @param conversationId - The ID of the conversation
     */
    async clearPendingGroupFromExternalCommit(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.clear_pending_group_from_external_commit(conversationId));
    }

    /**
     * Allows to mark the latest commit produced as "accepted" and be able to safely merge it
     * into the local group state
     *
     * @param conversationId - The group's ID
     */
    async commitAccepted(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.commit_accepted(conversationId));
    }

    /**
     * Allows to remove a pending proposal (rollback). Use this when backend rejects the proposal you just sent e.g. if permissions
     * have changed meanwhile.
     *
     * **CAUTION**: only use this when you had an explicit response from the Delivery Service
     * e.g. 403 or 409. Do not use otherwise e.g. 5xx responses, timeout etc..
     *
     * @param conversationId - The group's ID
     * @param proposalRef - A reference to the proposal to delete. You get one when using {@link CoreCrypto.newProposal}
     */
    async clearPendingProposal(conversationId: ConversationId, proposalRef: ProposalRef): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.clear_pending_proposal(conversationId, proposalRef));
    }

    /**
     * Allows to remove a pending commit (rollback). Use this when backend rejects the commit you just sent e.g. if permissions
     * have changed meanwhile.
     *
     * **CAUTION**: only use this when you had an explicit response from the Delivery Service
     * e.g. 403. Do not use otherwise e.g. 5xx responses, timeout etc..
     * **DO NOT** use when Delivery Service responds 409, pending state will be renewed
     * in {@link CoreCrypto.decryptMessage}
     *
     * @param conversationId - The group's ID
     */
    async clearPendingCommit(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.clear_pending_commit(conversationId));
    }

    /**
     * Derives a new key from the group
     *
     * @param conversationId - The group's ID
     * @param keyLength - the length of the key to be derived. If the value is higher than the
     * bounds of `u16` or the context hash * 255, an error will be returned
     *
     * @returns A `Uint8Array` representing the derived key
     */
    async exportSecretKey(conversationId: ConversationId, keyLength: number): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.export_secret_key(conversationId, keyLength));
    }

    /**
     * Returns all clients from group's members
     *
     * @param conversationId - The group's ID
     *
     * @returns A list of clients from the members of the group
     */
    async getClientIds(conversationId: ConversationId): Promise<ClientId[]> {
        return await CoreCryptoError.asyncMapErr(this.#cc.get_client_ids(conversationId));
    }

    /**
     * Allows {@link CoreCrypto} to act as a CSPRNG provider
     * @note The underlying CSPRNG algorithm is ChaCha20 and takes in account the external seed provider either at init time or provided with {@link CoreCrypto.reseedRng}
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
            throw new Error(`The seed length needs to be exactly 32 bytes. ${seed.length} bytes provided.`);
        }

        return await CoreCryptoError.asyncMapErr(this.#cc.reseed_rng(seed));
    }

    /**
     * Initiailizes the proteus client
     */
    async proteusInit(): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_init());
    }

    /**
     * Create a Proteus session using a prekey
     *
     * @param sessionId - ID of the Proteus session
     * @param prekey - CBOR-encoded Proteus prekey of the other client
     */
    async proteusSessionFromPrekey(sessionId: string, prekey: Uint8Array): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_session_from_prekey(sessionId, prekey));
    }

    /**
     * Create a Proteus session from a handshake message
     *
     * @param sessionId - ID of the Proteus session
     * @param envelope - CBOR-encoded Proteus message
     *
     * @returns A `Uint8Array` containing the message that was sent along with the session handshake
     */
    async proteusSessionFromMessage(sessionId: string, envelope: Uint8Array): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_session_from_message(sessionId, envelope));
    }

    /**
     * Locally persists a session to the keystore
     *
     * **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
     *
     * @param sessionId - ID of the Proteus session
     */
    async proteusSessionSave(sessionId: string): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_session_save(sessionId));
    }

    /**
     * Deletes a session
     * Note: this also deletes the persisted data within the keystore
     *
     * @param sessionId - ID of the Proteus session
     */
    async proteusSessionDelete(sessionId: string): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_session_delete(sessionId));
    }

    /**
     * Checks if a session exists
     *
     * @param sessionId - ID of the Proteus session
     *
     * @returns whether the session exists or not
     */
    async proteusSessionExists(sessionId: string): Promise<boolean> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_session_exists(sessionId));
    }

    /**
     * Decrypt an incoming message for an existing Proteus session
     *
     * @param sessionId - ID of the Proteus session
     * @param ciphertext - CBOR encoded, encrypted proteus message
     * @returns The decrypted payload contained within the message
     */
    async proteusDecrypt(sessionId: string, ciphertext: Uint8Array): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_decrypt(sessionId, ciphertext));
    }

    /**
     * Encrypt a message for a given Proteus session
     *
     * @param sessionId - ID of the Proteus session
     * @param plaintext - payload to encrypt
     * @returns The CBOR-serialized encrypted message
     */
    async proteusEncrypt(sessionId: string, plaintext: Uint8Array): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_encrypt(sessionId, plaintext));
    }

    /**
     * Batch encryption for proteus messages
     * This is used to minimize FFI roundtrips when used in the context of a multi-client session (i.e. conversation)
     *
     * @param sessions - List of Proteus session IDs to encrypt the message for
     * @param plaintext - payload to encrypt
     * @returns A map indexed by each session ID and the corresponding CBOR-serialized encrypted message for this session
     */
    async proteusEncryptBatched(sessions: string[], plaintext: Uint8Array): Promise<Map<string, Uint8Array>> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_encrypt_batched(sessions, plaintext));
    }

    /**
     * Creates a new prekey with the requested ID.
     *
     * @param prekeyId - ID of the PreKey to generate. This cannot be bigger than a u16
     * @returns: A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey
     */
    async proteusNewPrekey(prekeyId: number): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_new_prekey(prekeyId));
    }

    /**
     * Creates a new prekey with an automatically generated ID..
     *
     * @returns A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey accompanied by its ID
     */
    async proteusNewPrekeyAuto(): Promise<ProteusAutoPrekeyBundle> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_new_prekey_auto());
    }

    /**
     * Proteus last resort prekey stuff
     *
     * @returns A CBOR-serialize version of the PreKeyBundle associated with the last resort PreKey (holding the last resort prekey id)
     */
    async proteusLastResortPrekey(): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_last_resort_prekey());
    }

    /**
     * @returns The last resort PreKey id
     */
    static proteusLastResortPrekeyId(): number {
        this.#assertModuleLoaded();
        return this.#module.CoreCrypto.proteus_last_resort_prekey_id();
    }

    /**
     * Proteus public key fingerprint
     * It's basically the public key encoded as an hex string
     *
     * @returns Hex-encoded public key string
     */
    async proteusFingerprint(): Promise<string> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_fingerprint());
    }

    /**
     * Proteus session local fingerprint
     *
     * @param sessionId - ID of the Proteus session
     * @returns Hex-encoded public key string
     */
    async proteusFingerprintLocal(sessionId: string): Promise<string> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_fingerprint_local(sessionId));
    }

    /**
     * Proteus session remote fingerprint
     *
     * @param sessionId - ID of the Proteus session
     * @returns Hex-encoded public key string
     */
    async proteusFingerprintRemote(sessionId: string): Promise<string> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_fingerprint_remote(sessionId));
    }

    /**
     * Hex-encoded fingerprint of the given prekey
     *
     * @param prekey - the prekey bundle to get the fingerprint from
     * @returns Hex-encoded public key string
     **/
    static proteusFingerprintPrekeybundle(prekey: Uint8Array): string {
        try {
            return this.#module.CoreCrypto.proteus_fingerprint_prekeybundle(prekey);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Imports all the data stored by Cryptobox into the CoreCrypto keystore
     *
     * @param storeName - The name of the IndexedDB store where the data is stored
     */
    async proteusCryptoboxMigrate(storeName: string): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#cc.proteus_cryptobox_migrate(storeName));
    }

    /**
     * Note: this call clears out the code and resets it to 0 (aka no error)
     * @returns the last proteus error code that occured.
     */
    async proteusLastErrorCode(): Promise<number> {
        return await this.#cc.proteus_last_error_code();
    }

    /**
     * Creates an enrollment instance with private key material you can use in order to fetch
     * a new x509 certificate from the acme server.
     * Make sure to call {@link WireE2eIdentity.free} to dispose this instance and its associated
     * keying material.
     *
     * @param ciphersuite - For generating signing key material. Only {@link Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519} is supported currently
     */
    async newAcmeEnrollment(ciphersuite: Ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519): Promise<WireE2eIdentity> {
        if (ciphersuite !== Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) {
            throw new Error("This ACME ciphersuite isn't supported. Only `Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` is as of now");
        }

        const e2ei = await CoreCryptoError.asyncMapErr(this.#cc.new_acme_enrollment(ciphersuite));
        return new WireE2eIdentity(e2ei);
    }

    /**
     * Returns the current version of {@link CoreCrypto}
     *
     * @returns The `core-crypto-ffi` version as defined in its `Cargo.toml` file
     */
    static version(): string {
        this.#assertModuleLoaded();
        return this.#module.CoreCrypto.version();
    }
}

type JsonRawData = Uint8Array;
type AcmeAccount = Uint8Array;
type AcmeOrder = Uint8Array;

export class WireE2eIdentity {
    /** @hidden */
    #e2ei: CoreCryptoFfiTypes.FfiWireE2EIdentity;

    /** @hidden */
    constructor(e2ei: unknown) {
        this.#e2ei = e2ei as CoreCryptoFfiTypes.FfiWireE2EIdentity;
    }

    free() {
        this.#e2ei.free();
    }

    /**
     * Parses the response from `GET /acme/{provisioner-name}/directory`.
     * Use this {@link AcmeDirectory} in the next step to fetch the first nonce from the acme server. Use
     * {@link AcmeDirectory.newNonce}.
     *
     * @param directory HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
     */
    directoryResponse(directory: JsonRawData): AcmeDirectory {
        try {
            return this.#e2ei.directory_response(directory);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * For creating a new acme account. This returns a signed JWS-alike request body to send to
     * `POST /acme/{provisioner-name}/new-account`.
     *
     * @param directory you got from {@link directoryResponse}
     * @param previousNonce you got from calling `HEAD {@link AcmeDirectory.newNonce}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
     */
    newAccountRequest(directory: AcmeDirectory, previousNonce: string): JsonRawData {
        try {
            return this.#e2ei.new_account_request(directory, previousNonce);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/new-account`.
     * @param account HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
     */
    newAccountResponse(account: JsonRawData): AcmeAccount {
        try {
            return this.#e2ei.new_account_response(account);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Creates a new acme order for the handle (userId + display name) and the clientId.
     *
     * @param displayName human readable name displayed in the application e.g. `Smith, Alice M (QA)`
     * @param domain DNS name of owning backend e.g. `example.com`
     * @param clientId client identifier with user b64Url encoded & clientId hex encoded e.g. `impp:wireapp=NDUyMGUyMmY2YjA3NGU3NjkyZjE1NjJjZTAwMmQ2NTQ/6add501bacd1d90e@example.com`
     * @param handle user handle e.g. `impp:wireapp=alice.smith.qa@example.com`
     * @param expiryDays generated x509 certificate expiry
     * @param directory you got from {@link directoryResponse}
     * @param account you got from {@link newAccountResponse}
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/new-account`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    newOrderRequest(displayName: string, domain: string, clientId: string, handle: string, expiryDays: number, directory: AcmeDirectory, account: AcmeAccount, previousNonce: string): JsonRawData {
        try {
            return this.#e2ei.new_order_request(displayName, domain, clientId, handle, expiryDays, directory, account, previousNonce);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/new-order`.
     *
     * @param order HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    newOrderResponse(order: JsonRawData): NewAcmeOrder {
        try {
            return this.#e2ei.new_order_response(order);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Creates a new authorization request.
     *
     * @param url one of the URL in new order's authorizations (use {@link NewAcmeOrder.authorizations} from {@link newOrderResponse})
     * @param account you got from {@link newAccountResponse}
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/new-order` (or from the
     * previous to this method if you are creating the second authorization)
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
     */
    newAuthzRequest(url: string, account: AcmeAccount, previousNonce: string): JsonRawData {
        try {
            return this.#e2ei.new_authz_request(url, account, previousNonce);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/authz/{authz-id}`
     *
     * You then have to map the challenge from this authorization object. The `client_id_challenge`
     * will be the one with the `client_id_host` (you supplied to {@link newOrderRequest}) identifier,
     * the other will be your `handle_challenge`.
     *
     * @param authz HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
     */
    newAuthzResponse(authz: JsonRawData): NewAcmeAuthz {
        try {
            return this.#e2ei.new_authz_response(authz);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Generates a new client Dpop JWT token. It demonstrates proof of possession of the nonces
     * (from wire-server & acme server) and will be verified by the acme server when verifying the
     * challenge (in order to deliver a certificate).
     *
     * Then send it to `POST /clients/{id}/access-token`
     * {@link https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token} on wire-server.
     *
     * @param accessTokenUrl backend endpoint where this token will be sent. Should be this one {@link https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token}
     * @param userId an UUIDv4 uniquely identifying the user
     * @param clientId client identifier
     * @param domain owning backend domain e.g. `wire.com`
     * @param clientIdChallenge you found after {@link newAuthzResponse}
     * @param backendNonce you get by calling `GET /clients/token/nonce` on wire-server as defined here {@link https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/get_clients__client__nonce}
     * @param expiryDays token expiry in days
     */
    createDpopToken(accessTokenUrl: string, userId: string, clientId: bigint, domain: string, clientIdChallenge: AcmeChallenge, backendNonce: string, expiryDays: number): string {
        try {
            return this.#e2ei.create_dpop_token(accessTokenUrl, userId, clientId, domain, clientIdChallenge, backendNonce, expiryDays);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Creates a new challenge request for Wire Dpop challenge.
     *
     * @param accessToken returned by wire-server from https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token
     * @param dpopChallenge you found after {@link newAuthzResponse}
     * @param account you found after {@link newAccountResponse}
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    newDpopChallengeRequest(accessToken: string, dpopChallenge: AcmeChallenge, account: AcmeAccount, previousNonce: string): JsonRawData {
        try {
            return this.#e2ei.new_dpop_challenge_request(accessToken, dpopChallenge, account, previousNonce);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Creates a new challenge request for Wire Oidc challenge.
     *
     * @param idToken you get back from Identity Provider
     * @param oidcChallenge you found after {@link newAuthzResponse}
     * @param account you found after {@link newAccountResponse}
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    newOidcChallengeRequest(idToken: string, oidcChallenge: AcmeChallenge, account: AcmeAccount, previousNonce: string): JsonRawData {
        try {
            return this.#e2ei.new_oidc_challenge_request(idToken, oidcChallenge, account, previousNonce);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}`.
     *
     * @param challenge HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    newChallengeResponse(challenge: JsonRawData): void {
        try {
            return this.#e2ei.new_challenge_response(challenge);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Verifies that the previous challenge has been completed.
     *
     * @param orderUrl `location` header from http response you got from {@link newOrderResponse}
     * @param account you found after {@link newAccountResponse}
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/challenge/{challenge-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    checkOrderRequest(orderUrl: string, account: AcmeAccount, previousNonce: string): JsonRawData {
        try {
            return this.#e2ei.check_order_request(orderUrl, account, previousNonce);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/order/{order-id}`.
     *
     * @param order HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    checkOrderResponse(order: JsonRawData): AcmeOrder {
        try {
            return this.#e2ei.check_order_response(order);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Final step before fetching the certificate.
     *
     * @param order - order you got from {@link checkOrderResponse}
     * @param account - account you found after {@link newAccountResponse}
     * @param previousNonce - `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    finalizeRequest(order: AcmeOrder, account: AcmeAccount, previousNonce: string): JsonRawData {
        try {
            return this.#e2ei.finalize_request(order, account, previousNonce);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/order/{order-id}/finalize`.
     *
     * @param finalize HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    finalizeResponse(finalize: JsonRawData): AcmeFinalize {
        try {
            return this.#e2ei.finalize_response(finalize);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Creates a request for finally fetching the x509 certificate.
     *
     * @param finalize you got from {@link finalizeResponse}
     * @param account you got from {@link newAccountResponse}
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}/finalize`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2
     */
    certificateRequest(finalize: AcmeFinalize, account: AcmeAccount, previousNonce: string): JsonRawData {
        try {
            return this.#e2ei.certificate_request(finalize, account, previousNonce);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/certificate/{certificate-id}`.
     *
     * @param certificateChain HTTP string response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2
     */
    certificateResponse(certificateChain: string): Uint8Array[] {
        try {
            return this.#e2ei.certificate_response(certificateChain);
        } catch(e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }
}

/**
 * Holds URLs of all the standard ACME endpoint supported on an ACME server.
 * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
 */
export interface AcmeDirectory {
    /**
     * URL for fetching a new nonce. Use this only for creating a new account.
     *
     * @readonly
     */
    newNonce: string;
    /**
     * URL for creating a new account.
     *
     * @readonly
     */
    newAccount: string;
    /**
     * URL for creating a new order.
     *
     * @readonly
     */
    newOrder: string;
}

/**
 * Result of an order creation
 * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
 */
export interface NewAcmeOrder {
    /**
     * Contains raw JSON data of this order. This is parsed by the underlying Rust library hence should not be accessed
     *
     * @readonly
     */
    delegate: Uint8Array;
    /**
     * An authorization for each domain to create
     *
     * @readonly
     */
    authorizations: Uint8Array[];
}

/**
 * Result of an authorization creation.
 * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
 */
export interface NewAcmeAuthz {
    /**
     * DNS entry associated with those challenge
     *
     * @readonly
     */
    identifier: string;
    /**
     * Challenge for the clientId
     *
     * @readonly
     */
    wireHttpChallenge: AcmeChallenge | null;
    /**
     * Challenge for the userId and displayName
     *
     * @readonly
     */
    wireOidcChallenge: AcmeChallenge | null;
}

/**
 * For creating a challenge
 * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
 */
export interface AcmeChallenge {
    /**
     * Contains raw JSON data of this challenge. This is parsed by the underlying Rust library hence should not be accessed
     *
     * @readonly
     */
    delegate: Uint8Array;
    /**
     * URL of this challenge
     *
     * @readonly
     */
    url: string;
}
/**
 * Result from finalize.
 * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
 */
export interface AcmeFinalize {
    /**
     * Contains raw JSON data of this finalize. This is parsed by the underlying Rust library hence should not be accessed
     *
     * @readonly
     */
    delegate: Uint8Array;
    /**
     * URL of to use for the last request to fetch the x509 certificate
     *
     * @readonly
     */
    certificateUrl: string;
}
