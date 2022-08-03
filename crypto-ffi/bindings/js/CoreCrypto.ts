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

export interface ConversationConfiguration {
    admins?: Uint8Array[];
    ciphersuite?: Ciphersuite;
    keyRotationSpan?: number;
    externalSenders: Uint8Array[];
}

export type ConversationId = Uint8Array;

export interface CoreCryptoParams {
    databaseName: string;
    key: string;
    clientId: string;
    // This should be exactly 32 bytes
    entropySeed?: Uint8Array;
    wasmFilePath?: string;
}

export interface Invitee {
    id: Uint8Array;
    kp: Uint8Array;
}

export interface MemberAddedMessages {
    message: Uint8Array;
    welcome: Uint8Array;
}

export interface CommitBundle {
    message: Uint8Array;
    welcome?: Uint8Array;
}

export const enum ProposalType {
    Add,
    Remove,
    Update,
}

export interface ProposalArgs {
    conversationId: ConversationId;
}

export interface AddProposalArgs extends ProposalArgs {
    kp: Uint8Array;
}

export interface RemoveProposalArgs extends ProposalArgs {
    clientId: Uint8Array;
}

export class CoreCrypto {
    static #module: typeof CoreCryptoFfiTypes;
    #cc: CoreCryptoFfiTypes.CoreCrypto;

    static async init({ databaseName, key, clientId, wasmFilePath, entropySeed }: CoreCryptoParams): Promise<CoreCrypto> {
        if (!this.#module) {
            const wasmImportArgs = wasmFilePath ? { importHook: () => wasmFilePath } : undefined;
            const exports = (await wasm(wasmImportArgs)) as typeof CoreCryptoFfiTypes;
            this.#module = exports;
        }
        const cc = await this.#module.CoreCrypto._internal_new(databaseName, key, clientId, entropySeed);
        return new this(cc);
    }

    private constructor(cc: CoreCryptoFfiTypes.CoreCrypto) {
        this.#cc = cc;
    }

    async wipe() {
        await this.#cc.wipe();
    }

    async close() {
        await this.#cc.close();
    }

    async conversationExists(conversationId: ConversationId): Promise<boolean> {
        return await this.#cc.conversation_exists(conversationId);
    }

    async createConversation(
        conversationId: ConversationId,
        { ciphersuite, keyRotationSpan, externalSenders }: ConversationConfiguration = { externalSenders: [] }
    ) {
        const config = new CoreCrypto.#module.ConversationConfiguration(
            ciphersuite,
            keyRotationSpan,
            externalSenders,
        );
        const ret = await this.#cc.create_conversation(conversationId, config, externalSenders);
        return ret;
    }

    async decryptMessage(conversationId: ConversationId, payload: Uint8Array): Promise<Uint8Array | undefined> {
        return await this.#cc.decrypt_message(
            conversationId,
            payload
        );
    }

    async encryptMessage(conversationId: ConversationId, message: Uint8Array): Promise<Uint8Array> {
        return await this.#cc.encrypt_message(
            conversationId,
            message
        );
    }

    async processWelcomeMessage(welcomeMessage: Uint8Array): Promise<ConversationId> {
        return await this.#cc.process_welcome_message(welcomeMessage);
    }

    async clientPublicKey(): Promise<Uint8Array> {
        return await this.#cc.client_public_key();
    }

    async clientValidKeypackagesCount(): Promise<number> {
        return await this.#cc.client_valid_keypackages_count();
    }

    async clientKeypackages(amountRequested: number): Promise<Array<Uint8Array>> {
        return await this.#cc.client_keypackages(amountRequested);
    }

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
        };

        return ret;
    }

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
        };

        return ret
    }

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

    // This should be exactly 32 bytes
    async reseedRng(seed: Uint8Array): Promise<void> {
        return await this.#cc.reseed_rng(seed);
    }

    async randomBytes(length: number): Promise<Uint8Array> {
        return await this.#cc.random_bytes(length);
    }

    static version(): string {
        if (!this.#module) {
            throw new Error(
                "Internal module hasn't been initialized. Please use `await CoreCrypto.init(params)`!"
            );
        }
        return this.#module.version();
    }
}
