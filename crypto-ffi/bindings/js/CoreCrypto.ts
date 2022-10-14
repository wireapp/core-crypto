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
 * Alias for an MLS generic commit.
 * It contains:
 * * MLS Commit that needs to be fanned out to other (existing) members of the conversation
 * * (Optional) MLS Welcome message that needs to be fanned out to the clients newly added to the conversation (if any)
 * * TLS-serialized MLS PublicGroupState (GroupInfo in draft-15) which is required for joining a group by external commit + some metadatas for optimizations
 * (For final version. Requires to be implemented in the Delivery Service)
 * This is a freeform, uninspected buffer.
 */
export type TlsCommitBundle = Uint8Array;

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
     * TLS-serialized MLS PublicGroupState (GroupInfo in draft-15) which is required for joining a group by external commit
     *
     * @readonly
     */
    publicGroupState: Uint8Array;
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
     * TLS-serialized MLS PublicGroupState (GroupInfo in draft-15) which is required for joining a group by external commit
     *
     * @readonly
     */
    publicGroupState: Uint8Array;
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
     * TLS-serialized MLS Public Group State (aka Group Info) which becomes valid when the external commit is accepted by the Delivery Service
     * with {@link CoreCrypto.mergePendingGroupFromExternalCommit}
     *
     * @readonly
     */
    publicGroupState: Uint8Array;
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

        const ret: MemberAddedMessages = {
            welcome: ffiRet.welcome,
            commit: ffiRet.commit,
            publicGroupState: ffiRet.public_group_state,
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

        const ret: CommitBundle = {
            welcome: ffiRet.welcome,
            commit: ffiRet.commit,
            publicGroupState: ffiRet.public_group_state,
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

        const ret: CommitBundle = {
            welcome: ffiRet.welcome,
            commit: ffiRet.commit,
            publicGroupState: ffiRet.public_group_state,
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

            return ffiCommitBundle ? {
                welcome: ffiCommitBundle.welcome,
                commit: ffiCommitBundle.commit,
                publicGroupState: ffiCommitBundle.public_group_state,
            } : undefined;
    }

    /**
     * Adds new clients to a conversation, assuming the current client has the right to add new clients to the conversation.
     * The returned {@link CommitBundle} is a TLS struct that needs to be fanned out to Delivery Service in order to validate the commit.
     * It also contains a Welcome message the Delivery Service will forward to invited clients and
     * an updated PublicGroupState required by clients willing to join the group by an external commit.
     *
     * **CAUTION**: {@link CoreCrypto.commitAccepted} **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
     * '200 OK' to the {@link CommitBundle} upload. It will "merge" the commit locally i.e. increment the local group
     * epoch, use new encryption secrets etc...
     *
     * @param conversationId - The ID of the conversation
     * @param clients - Array of {@link Invitee} (which are Client ID / KeyPackage pairs)
     *
     * @returns A {@link CommitBundle} byte array to fan out to the Delivery Service
     */
    async finalAddClientsToConversation(
        conversationId: ConversationId,
        clients: Invitee[]
    ): Promise<TlsCommitBundle> {
        const ffiClients = clients.map(
            (invitee) => new CoreCrypto.#module.Invitee(invitee.id, invitee.kp)
        );

        const ret: TlsCommitBundle = await this.#cc.add_clients_to_conversation(conversationId, ffiClients);

        ffiClients.forEach(c => c.free());

        return ret;
    }

    /**
     * Removes the provided clients from a conversation; Assuming those clients exist and the current client is allowed
     * to do so, otherwise this operation does nothing.
     *
     * The returned {@link CommitBundle} is a TLS struct that needs to be fanned out to Delivery Service in order to validate the commit.
     * It also contains a Welcome message the Delivery Service will forward to invited clients and
     * an updated PublicGroupState required by clients willing to join the group by an external commit.
     *
     * **CAUTION**: {@link CoreCrypto.commitAccepted} **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
     * '200 OK' to the {@link CommitBundle} upload. It will "merge" the commit locally i.e. increment the local group
     * epoch, use new encryption secrets etc...
     *
     * @param conversationId - The ID of the conversation
     * @param clientIds - Array of Client IDs to remove.
     *
     * @returns A {@link CommitBundle} byte array to fan out to the Delivery Service, or `undefined` if for any reason, the operation would result in an empty commit
     */
    async finalRemoveClientsFromConversation(
        conversationId: ConversationId,
        clientIds: ClientId[]
    ): Promise<TlsCommitBundle> {
        return await this.#cc.remove_clients_from_conversation(conversationId, clientIds);
    }

    /**
     * Creates an update commit which forces every client to update their keypackages in the conversation
     *
     * The returned {@link CommitBundle} is a TLS struct that needs to be fanned out to Delivery Service in order to validate the commit.
     * It also contains a Welcome message the Delivery Service will forward to invited clients and
     * an updated PublicGroupState required by clients willing to join the group by an external commit.
     *
     * **CAUTION**: {@link CoreCrypto.commitAccepted} **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
     * '200 OK' to the {@link CommitBundle} upload. It will "merge" the commit locally i.e. increment the local group
     * epoch, use new encryption secrets etc...
     *
     * @param conversationId - The ID of the conversation
     *
     * @returns A {@link CommitBundle} byte array to fan out to the Delivery Service
     */
    async finalUpdateKeyingMaterial(conversationId: ConversationId): Promise<TlsCommitBundle> {
        return await this.#cc.update_keying_material(conversationId);
    }

    /**
     * Commits the local pending proposals and returns the {@link CommitBundle} object containing what can result from this operation.
     *
     * The returned {@link CommitBundle} is a TLS struct that needs to be fanned out to Delivery Service in order to validate the commit.
     * It also contains a Welcome message the Delivery Service will forward to invited clients and
     * an updated PublicGroupState required by clients willing to join the group by an external commit.
     *
     * **CAUTION**: {@link CoreCrypto.commitAccepted} **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
     * '200 OK' to the {@link CommitBundle} upload. It will "merge" the commit locally i.e. increment the local group
     * epoch, use new encryption secrets etc...
     *
     * @param conversationId - The ID of the conversation
     *
     * @returns A {@link CommitBundle} byte array to fan out to the Delivery Service or `undefined` when there was no pending proposal to commit
     */
    async finalCommitPendingProposals(conversationId: ConversationId): Promise<TlsCommitBundle | undefined> {
        return await this.#cc.commit_pending_proposals(conversationId);
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
     * @param publicGroupState - The public group state that can be fetched from the backend for a given conversation
     * @returns see {@link ConversationInitBundle}
     */
    async joinByExternalCommit(publicGroupState: Uint8Array): Promise<ConversationInitBundle> {
        const ffiInitMessage: CoreCryptoFfiTypes.ConversationInitBundle = await this.#cc.join_by_external_commit(publicGroupState);

        const ret: ConversationInitBundle = {
            conversationId: ffiInitMessage.conversation_id,
            commit: ffiInitMessage.commit,
            publicGroupState: ffiInitMessage.public_group_state,
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
