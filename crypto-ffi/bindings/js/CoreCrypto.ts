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

import type { Ciphersuite } from "./wasm/core-crypto-ffi";
export type { Ciphersuite } from "./wasm/core-crypto-ffi";

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
 * Alias for convesation IDs.
 * This is a freeform, uninspected buffer.
 */
export type ConversationId = Uint8Array;

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
    id: Uint8Array;
    /**
     * MLS KeyPackage belonging to the aforementioned client
     */
    kp: Uint8Array;
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
    message: Uint8Array;
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
    message: Uint8Array;
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

export interface MlsConversationInitMessage {
    /**
     * Group ID
     *
     * @readonly
     */
    group: Uint8Array;
    /**
     * TLS-serialized MLS Commit that needs to be fanned out
     *
     * @readonly
     */
    message: Uint8Array;
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
     * List of proposals that were retrieved from the decrypted message, in addition to the pending local proposals
     */
    proposals: Uint8Array[];
    /**
     * It is set to false if ingesting this MLS message has resulted in the client being removed from the group (i.e. a Remove commit)
     */
    isActive: boolean;
    /**
     * Commit delay hint (in milliseconds) to prevent clients from hammering the server with epoch changes
     */
    commitDelay?: number;
}

/**
 * MLS Proposal type
 */
export const enum ProposalType {
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
    clientId: Uint8Array;
}

/**
 * MLS External Proposal type
 */
export const enum ExternalProposalType {
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
    static async init({ databaseName, key, clientId, wasmFilePath, entropySeed }: CoreCryptoParams): Promise<CoreCrypto> {
        if (!this.#module) {
            const wasmImportArgs = wasmFilePath ? { importHook: () => wasmFilePath } : undefined;
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
     * Wipes and destroys the local storage of a given conversation / MLS group
     *
     * @param conversationId - The ID of the conversation to remove
     */
    async wipeConversation(conversationId: ConversationId): Promise<void> {
        return await this.#cc.wipe_conversation(conversationId);
    }

    /**
     * Creates an update commit which forces every client to update their keypackages in the conversation
     *
     * @param conversationId - The ID of the conversation
     */
    async updateKeyingMaterial(conversationId: ConversationId): Promise<CommitBundle> {
        const ffiRet: CoreCryptoFfiTypes.CommitBundle = await this.#cc.update_keying_material(
            conversationId
        );

        const ret: CommitBundle = {
            welcome: ffiRet.welcome,
            message: ffiRet.message,
            publicGroupState: ffiRet.public_group_state,
        };

        return ret;
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
        const { admins, ciphersuite, keyRotationSpan, externalSenders } = configuration ?? {};
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
     * @returns Either a decrypted message payload or `undefined` - This happens when the encrypted payload contains a system message such a proposal or commit
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
     * Adds new clients to a conversation, assuming the current client has the right to add new clients to the conversation
     * The returned {@link MemberAddedMessages} object contains a TLS-serialized MLS commit (the `message`) that needs to be
     * fanned out to existing members of the conversation and a TLS-serialized MLS Welcome message that needs to be fanned out to the
     *
     * @param conversationId - The ID of the conversation
     * @param clients - Array of {@link Invitee} (which are Client ID / KeyPackage pairs)
     *
     * @returns A {@link MemberAddedMessages} object
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
            message: ffiRet.message,
            publicGroupState: ffiRet.public_group_state,
        };

        return ret;
    }

    /**
     * Removes the provided clients from a conversation; Assuming those clients exist and the current client is allowed to do so, otherwise this operation does nothing
     *
     * @param conversationId - The ID of the conversation
     * @param clientIds - Array of Client IDs to remove.
     *
     * @returns A TLS-serialized MLS commit acting on the removal of those clients, or `undefined` if for any reason, the operation would result in an empty commit
     */
    async removeClientsFromConversation(
        conversationId: ConversationId,
        clientIds: Uint8Array[]
    ): Promise<CommitBundle> {
        const ffiRet: CoreCryptoFfiTypes.CommitBundle = await this.#cc.remove_clients_from_conversation(
            conversationId,
            clientIds
        );

        const ret: CommitBundle = {
            welcome: ffiRet.welcome,
            message: ffiRet.message,
            publicGroupState: ffiRet.public_group_state,
        };

        return ret;
    }

    /**
     * Creates a new proposal for the provided Conversation ID
     *
     * @param proposalType - The type of proposal, see {@link ProposalType}
     * @param args - The arguments of the proposal, see {@link ProposalArgs}, {@link AddProposalArgs} or {@link RemoveProposalArgs}
     *
     * @returns A TLS-serialized MLS proposal
     */
    async newProposal(
        proposalType: ProposalType,
        args: ProposalArgs | AddProposalArgs | RemoveProposalArgs
    ): Promise<Uint8Array> {
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
     * Allows to create an external commit to "apply" to join a group through its public group state
     *
     * Also see the second step of this process: {@link CoreCrypto.mergePendingGroupFromExternalCommit}
     *
     * @param publicGroupState - The public group state that can be fetched from the backend for a given conversation
     * @returns see {@link MlsConversationInitMessage}
     */
    async joinByExternalCommit(publicGroupState: Uint8Array): Promise<MlsConversationInitMessage> {
        const ffiInitMessage: CoreCryptoFfiTypes.MlsConversationInitMessage = await this.#cc.join_by_external_commit(publicGroupState);

        const ret: MlsConversationInitMessage = {
            group: ffiInitMessage.group,
            message: ffiInitMessage.message
        };

        return ret;
    }

    /**
     * This is the second step of the process of joining a group through an external commit
     *
     * This step makes the group operational and ready to encrypt/decrypt message
     *
     * @param conversationId - The ID of the conversation
     * @param configuration - Configuration of the group, see {@link ConversationConfiguration}
     */
    async mergePendingGroupFromExternalCommit(conversationId: ConversationId, configuration: ConversationConfiguration): Promise<void> {
        const { admins, ciphersuite, keyRotationSpan, externalSenders } = configuration ?? {};
        const config = new CoreCrypto.#module.ConversationConfiguration(
            admins,
            ciphersuite,
            keyRotationSpan,
            externalSenders,
        );
        return await this.#cc.merge_pending_group_from_external_commit(conversationId, config);
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
     * Commits the local pending proposals and returns the {@link CommitBundle} object containing what can result from this operation
     *
     * @param conversationId - The ID of the conversation
     * @returns see {@link CommitBundle}
     */
    async commitPendingProposals(conversationId: ConversationId): Promise<CommitBundle> {
        const ffiCommitBundle: CoreCryptoFfiTypes.CommitBundle = await this.#cc.commit_pending_proposals(
            conversationId
        );

        const ret: CommitBundle = {
            welcome: ffiCommitBundle.welcome,
            message: ffiCommitBundle.message,
            publicGroupState: ffiCommitBundle.public_group_state,
        };

        return ret;
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
