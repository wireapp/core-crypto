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
     * List of client IDs with administrative permissions
     * Note: This is currently unused
     */
    admins?: Uint8Array[];
    /**
     * Conversation ciphersuite
     */
    ciphersuite?: Ciphersuite;
    /**
     * Duration in seconds after which we will automatically force a self_update commit
     * Note: This isn't currently implemented
     */
    keyRotationSpan?: number;
    /**
     * List of client IDs that are allowed to be external senders of commits
     */
    externalSenders?: Uint8Array[];
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
 * Params for CoreCrypto initialization
 * Please note that the `entropySeed` parameter MUST be exactly 32 bytes
 */
export interface CoreCryptoParams {
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
     * MLS Client ID.
     * This should stay consistent as it will be verified against the stored signature & identity to validate the persisted credential
     */
    clientId: string;
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
    authorize: (conversationId: Uint8Array, clientId: Uint8Array) => boolean;

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
    userAuthorize: (conversationId: Uint8Array, externalClientId: Uint8Array, existingClients: Uint8Array[]) => boolean;

    /**
     * Callback to ensure that the given `clientId` belongs to one of the provided `existingClients`
     * This basically allows to defer the client ID parsing logic to the caller - because CoreCrypto is oblivious to such things
     *
     * @param clientId - id of a client
     * @param existingClients - all the clients currently within the MLS group
     */
    clientIsExistingGroupUser: (clientId: Uint8Array, existingClients: Uint8Array[]) => boolean;
}

/**
 * Wrapper for the WASM-compiled version of CoreCrypto
 */
export class CoreCrypto {
    /** @hidden */
    static #module: typeof CoreCryptoFfiTypes;
    /** @hidden */
    #cc: CoreCryptoFfiTypes.CoreCrypto;

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
    static async init({databaseName, key, clientId, wasmFilePath, entropySeed}: CoreCryptoParams): Promise<CoreCrypto> {
        if (!this.#module) {
            const wasmImportArgs = wasmFilePath ? {importHook: () => wasmFilePath} : undefined;
            const exports = (await wasm(wasmImportArgs)) as typeof CoreCryptoFfiTypes;
            this.#module = exports;
        }
        const cc = await this.#module.CoreCrypto._internal_new(databaseName, key, clientId, entropySeed);
        return new this(cc);
    }

    /**
     * Almost identical to {@link CoreCrypto.init} but allows a 2 phase initialization of MLS.
     * First, calling this will set up the keystore and will allow generating proteus prekeys.
     * Then, those keys can be traded for a clientId.
     * Use this clientId to initialize MLS with {@link CoreCrypto.mlsInit}.
     */
    static async deferredInit(databaseName: string, key: string, entropySeed?: Uint8Array, wasmFilePath?: string): Promise<CoreCrypto> {
        if (!this.#module) {
            const wasmImportArgs = wasmFilePath ? {importHook: () => wasmFilePath} : undefined;
            const exports = (await wasm(wasmImportArgs)) as typeof CoreCryptoFfiTypes;
            this.#module = exports;
        }
        const cc = await this.#module.CoreCrypto.deferred_init(databaseName, key, entropySeed);
        return new this(cc);
    }

    /**
     * Use this after {@link CoreCrypto.deferredInit} when you have a clientId. It initializes MLS.
     *
     * @param clientId - {@link CoreCryptoParams#clientId} but required
     */
    async mlsInit(clientId: string): Promise<void> {
        return await this.#cc.mls_init(clientId);
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
        await this.#cc.wipe();
    }

    /**
     * Closes this {@link CoreCrypto} instance and deallocates all loaded resources
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be useable after a call to this method, but there's no way to express this requirement in TypeScript so you'll get errors instead!
     */
    async close() {
        await this.#cc.close();
    }

    /**
     * Registers the callbacks for CoreCrypto to use in order to gain additional information
     *
     * @param callbacks - Any interface following the {@link CoreCryptoCallbacks} interface
     */
    registerCallbacks(callbacks: CoreCryptoCallbacks) {
        const wasmCallbacks = new CoreCrypto.#module.CoreCryptoWasmCallbacks(
            callbacks.authorize,
            callbacks.userAuthorize,
            callbacks.clientIsExistingGroupUser
        );
        this.#cc.set_callbacks(wasmCallbacks);
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
        return await this.#cc.conversation_exists(conversationId);
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
        return await this.#cc.conversation_epoch(conversationId);
    }

    /**
     * Wipes and destroys the local storage of a given conversation / MLS group
     *
     * @param conversationId - The ID of the conversation to remove
     */
    async wipeConversation(conversationId: ConversationId): Promise<void> {
        return await this.#cc.wipe_conversation(conversationId);
    }

    /**
     * Creates a new conversation with the current client being the sole member
     * You will want to use {@link CoreCrypto.addClientsToConversation} afterwards to add clients to this conversation
     *
     * @param conversationId - The conversation ID; You can either make them random or let the backend attribute MLS group IDs
     * @param configuration.admins - An array of client IDs that will have administrative permissions over the group
     * @param configuration.ciphersuite - The {@link Ciphersuite} that is chosen to be the group's
     * @param configuration.keyRotationSpan - The amount of time in milliseconds after which the MLS Keypackages will be rotated
     * @param configuration.externalSenders - Array of Client IDs that are qualified as external senders within the group
     */
    async createConversation(
        conversationId: ConversationId,
        configuration: ConversationConfiguration = {}
    ) {
        const {admins, ciphersuite, keyRotationSpan, externalSenders} = configuration || {};
        const config = new CoreCrypto.#module.ConversationConfiguration(
            admins,
            ciphersuite,
            keyRotationSpan,
            externalSenders,
        );
        const ret = await this.#cc.create_conversation(conversationId, config);
        return ret;
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
        const ffiDecryptedMessage: CoreCryptoFfiTypes.DecryptedMessage = await this.#cc.decrypt_message(
            conversationId,
            payload
        );

        const commitDelay = ffiDecryptedMessage.commit_delay ?
            ffiDecryptedMessage.commit_delay * 1000 :
            undefined;

        const ret: DecryptedMessage = {
            message: ffiDecryptedMessage.message,
            proposals: ffiDecryptedMessage.proposals,
            isActive: ffiDecryptedMessage.is_active,
            senderClientId: ffiDecryptedMessage.sender_client_id,
            commitDelay,
            hasEpochChanged: ffiDecryptedMessage.has_epoch_changed,
        };

        return ret;
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
        return await this.#cc.encrypt_message(
            conversationId,
            message
        );
    }

    /**
     * Ingest a TLS-serialized MLS welcome message to join a an existing MLS group
     *
     * @param welcomeMessage - TLS-serialized MLS Welcome message
     * @returns The conversation ID of the newly joined group. You can use the same ID to decrypt/encrypt messages
     */
    async processWelcomeMessage(welcomeMessage: Uint8Array): Promise<ConversationId> {
        return await this.#cc.process_welcome_message(welcomeMessage);
    }

    /**
     * @returns The client's public key
     */
    async clientPublicKey(): Promise<Uint8Array> {
        return await this.#cc.client_public_key();
    }

    /**
     * @returns The amount of valid, non-expired KeyPackages that are persisted in the backing storage
     */
    async clientValidKeypackagesCount(): Promise<number> {
        return await this.#cc.client_valid_keypackages_count();
    }

    /**
     * Fetches a requested amount of keypackages
     *
     * @param amountRequested - The amount of keypackages requested
     * @returns An array of length `amountRequested` containing TLS-serialized KeyPackages
     */
    async clientKeypackages(amountRequested: number): Promise<Array<Uint8Array>> {
        return await this.#cc.client_keypackages(amountRequested);
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
        const ffiClients = clients.map(
            (invitee) => new CoreCrypto.#module.Invitee(invitee.id, invitee.kp)
        );

        const ffiRet: CoreCryptoFfiTypes.MemberAddedMessages = await this.#cc.add_clients_to_conversation(
            conversationId,
            ffiClients
        );

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
        const ffiRet: CoreCryptoFfiTypes.CommitBundle = await this.#cc.remove_clients_from_conversation(
            conversationId,
            clientIds
        );

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
        const ffiRet: CoreCryptoFfiTypes.CommitBundle = await this.#cc.update_keying_material(
            conversationId
        );

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
        const ffiCommitBundle: CoreCryptoFfiTypes.CommitBundle | undefined = await this.#cc.commit_pending_proposals(
            conversationId
        );

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
                return await this.#cc.new_add_proposal(
                    args.conversationId,
                    (args as AddProposalArgs).kp
                );
            }
            case ProposalType.Remove: {
                if (!(args as RemoveProposalArgs).clientId) {
                    throw new Error(
                        "clientId is not contained in the proposal arguments"
                    );
                }
                return await this.#cc.new_remove_proposal(
                    args.conversationId,
                    (args as RemoveProposalArgs).clientId
                );
            }
            case ProposalType.Update: {
                return await this.#cc.new_update_proposal(
                    args.conversationId
                );
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
                return await this.#cc.new_external_add_proposal(args.conversationId, args.epoch);
            }
            case ExternalProposalType.Remove: {
                if (!(args as ExternalRemoveProposalArgs).keyPackageRef) {
                    throw new Error("keyPackageRef is not contained in the external proposal arguments");
                }

                return await this.#cc.new_external_remove_proposal(
                    args.conversationId,
                    args.epoch,
                    (args as ExternalRemoveProposalArgs).keyPackageRef
                );
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
        return await this.#cc.export_group_state(conversationId);
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
     * @returns see {@link ConversationInitBundle}
     */
    async joinByExternalCommit(publicGroupState: Uint8Array): Promise<ConversationInitBundle> {
        const ffiInitMessage: CoreCryptoFfiTypes.ConversationInitBundle = await this.#cc.join_by_external_commit(publicGroupState);

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
    }

    /**
     * This merges the commit generated by {@link CoreCrypto.joinByExternalCommit}, persists the group permanently
     * and deletes the temporary one. This step makes the group operational and ready to encrypt/decrypt message
     *
     * @param conversationId - The ID of the conversation
     * @param configuration - Configuration of the group, see {@link ConversationConfiguration}
     */
    async mergePendingGroupFromExternalCommit(conversationId: ConversationId, configuration: ConversationConfiguration): Promise<void> {
        const {admins, ciphersuite, keyRotationSpan, externalSenders} = configuration || {};
        const config = new CoreCrypto.#module.ConversationConfiguration(
            admins,
            ciphersuite,
            keyRotationSpan,
            externalSenders,
        );
        return await this.#cc.merge_pending_group_from_external_commit(conversationId, config);
    }

    /**
     * In case the external commit generated by {@link CoreCrypto.joinByExternalCommit} is rejected by the Delivery Service, and we
     * want to abort this external commit once for all, we can wipe out the pending group from the keystore in order
     * not to waste space
     *
     * @param conversationId - The ID of the conversation
     */
    async clearPendingGroupFromExternalCommit(conversationId: ConversationId): Promise<void> {
        return await this.#cc.clear_pending_group_from_external_commit(conversationId);
    }

    /**
     * Allows to mark the latest commit produced as "accepted" and be able to safely merge it
     * into the local group state
     *
     * @param conversationId - The group's ID
     */
    async commitAccepted(conversationId: ConversationId): Promise<void> {
        return await this.#cc.commit_accepted(conversationId);
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
        return await this.#cc.clear_pending_proposal(conversationId, proposalRef);
    }

    /**
     * Allows to remove a pending commit (rollback). Use this when backend rejects the commit you just sent e.g. if permissions
     * have changed meanwhile.
     *
     * **CAUTION**: only use this when you had an explicit response from the Delivery Service
     * e.g. 403. Do not use otherwise e.g. 5xx responses, timeout etc..
     * **DO NOT** use when Delivery Service responds 409, pending state will be renewed
     * in {@link CoreCrypto.decrypt_message}
     *
     * @param conversationId - The group's ID
     */
    async clearPendingCommit(conversationId: ConversationId): Promise<void> {
        return await this.#cc.clear_pending_commit(conversationId);
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
        return await this.#cc.export_secret_key(conversationId, keyLength);
    }

    /**
     * Returns all clients from group's members
     *
     * @param conversationId - The group's ID
     *
     * @returns A list of clients from the members of the group
     */
    async getClientIds(conversationId: ConversationId): Promise<ClientId[]> {
        return await this.#cc.get_client_ids(conversationId);
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
        return await this.#cc.random_bytes(length);
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

        return await this.#cc.reseed_rng(seed);
    }

    /**
     * Initiailizes the proteus client
     */
    async proteusInit(): Promise<void> {
        return await this.#cc.proteus_init();
    }

    /**
     * Create a Proteus session using a prekey
     *
     * @param sessionId - ID of the Proteus session
     * @param prekey - CBOR-encoded Proteus prekey of the other client
     */
    async proteusSessionFromPrekey(sessionId: string, prekey: Uint8Array): Promise<void> {
        return await this.#cc.proteus_session_from_prekey(sessionId, prekey);
    }

    /**
     * Create a Proteus session from a handshake message
     *
     * @param sessionId - ID of the Proteus session
     * @param envelope - CBOR-encoded Proteus message
     */
    async proteusSessionFromMessage(sessionId: string, envelope: Uint8Array): Promise<void> {
        return await this.#cc.proteus_session_from_message(sessionId, envelope);
    }

    /**
     * Locally persists a session to the keystore
     *
     * @param sessionId - ID of the Proteus session
     */
    async proteusSessionSave(sessionId: string): Promise<void> {
        return await this.#cc.proteus_session_save(sessionId);
    }

    /**
     * Deletes a session
     * Note: this also deletes the persisted data within the keystore
     *
     * @param sessionId - ID of the Proteus session
     */
    async proteusSessionDelete(sessionId: string): Promise<void> {
        return await this.#cc.proteus_session_delete(sessionId);
    }

    /**
     * Checks if a session exists
     *
     * @param sessionId - ID of the Proteus session
     */
    async proteusSessionExists(sessionId: string): Promise<void> {
        return await this.#cc.proteus_session_exists(sessionId);
    }

    /**
     * Decrypt an incoming message for an existing Proteus session
     *
     * @param sessionId - ID of the Proteus session
     * @param ciphertext - CBOR encoded, encrypted proteus message
     * @returns The decrypted payload contained within the message
     */
    async proteusDecrypt(sessionId: string, ciphertext: Uint8Array): Promise<Uint8Array> {
        return await this.#cc.proteus_decrypt(sessionId, ciphertext);
    }

    /**
     * Encrypt a message for a given Proteus session
     *
     * @param sessionId - ID of the Proteus session
     * @param plaintext - payload to encrypt
     * @returns The CBOR-serialized encrypted message
     */
    async proteusEncrypt(sessionId: string, plaintext: Uint8Array): Promise<Uint8Array> {
        return await this.#cc.proteus_encrypt(sessionId, plaintext);
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
        return await this.#cc.proteus_encrypt_batched(sessions, plaintext);
    }

    /**
     * Creates a new prekey with the requested ID.
     *
     * @param prekeyId - ID of the PreKey to generate. This cannot be bigger than a u16
     * @returns: A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey
     */
    async proteusNewPrekey(prekeyId: number): Promise<Uint8Array> {
        return await this.#cc.proteus_new_prekey(prekeyId);
    }

    /**
     * Proteus public key fingerprint
     * It's basically the public key encoded as an hex string
     *
     * @returns Hex-encoded public key string
     */
    async proteusFingerprint(): Promise<string> {
        return await this.#cc.proteus_fingerprint();
    }

    /**
     * Proteus session local fingerprint
     *
     * @param sessionId - ID of the Proteus session
     * @returns Hex-encoded public key string
     */
    async proteusFingerprintLocal(sessionId: string): Promise<string> {
        return await this.#cc.proteus_fingerprint_local(sessionId);
    }

    /**
     * Proteus session remote fingerprint
     *
     * @param sessionId - ID of the Proteus session
     * @returns Hex-encoded public key string
     */
    async proteusFingerprintRemote(sessionId: string): Promise<string> {
        return await this.#cc.proteus_fingerprint_remote(sessionId);
    }

    /**
     * Hex-encoded fingerprint of the given prekey
     *
     * @param prekey - the prekey bundle to get the fingerprint from
     * @returns Hex-encoded public key string
    **/
    static proteusFingerprintPrekeybundle(prekey: Uint8Array): string {
        return this.#module.CoreCrypto.proteus_fingerprint_prekeybundle(prekey);
    }

    /**
     * Imports all the data stored by Cryptobox into the CoreCrypto keystore
     *
     * @param storeName - The name of the IndexedDB store where the data is stored
     */
    async proteusCryptoboxMigrate(storeName: string): Promise<void> {
        return await this.#cc.proteus_cryptobox_migrate(storeName);
    }

    /**
     * Returns the current version of {@link CoreCrypto}
     *
     * @returns The `core-crypto-ffi` version as defined in its `Cargo.toml` file
     */
    static version(): string {
        if (!this.#module) {
            throw new Error(
                "Internal module hasn't been initialized. Please use `await CoreCrypto.init(params)`!"
            );
        }
        return this.#module.version();
    }
}
