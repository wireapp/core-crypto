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
}

export type ConversationId = Uint8Array;

export interface CoreCryptoParams {
    databaseName: string;
    key: string;
    clientId: string;
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

export interface ConversationLeaveMessages {
    self_removal_proposal: Uint8Array;
    other_clients_removal_commit: Uint8Array;
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

    static async init({ databaseName, key, clientId, wasmFilePath }: CoreCryptoParams): Promise<CoreCrypto> {
        if (!this.#module) {
            const wasmImportArgs = wasmFilePath ? { importHook: () => wasmFilePath } : undefined;
            const exports = (await wasm(wasmImportArgs)) as typeof CoreCryptoFfiTypes;
            this.#module = exports;
        }
        const cc = await this.#module.CoreCrypto._internal_new(databaseName, key, clientId);
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

    conversationExists(conversationId: ConversationId): boolean {
        return this.#cc.conversation_exists(conversationId);
    }

    async createConversation(
        conversationId: ConversationId,
        { ciphersuite, keyRotationSpan }: ConversationConfiguration = {}
    ) {
        const config = new CoreCrypto.#module.ConversationConfiguration(
            ciphersuite,
            keyRotationSpan
        );
        const ret = await this.#cc.create_conversation(conversationId, config);
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

    clientPublicKey(): Uint8Array {
        return this.#cc.client_public_key();
    }

    async clientKeypackages(amountRequested: number): Promise<Array<Uint8Array>> {
        return await this.#cc.client_keypackages(amountRequested);
    }

    async addClientsToConversation(
        conversationId: ConversationId,
        clients: Invitee[]
    ): Promise<MemberAddedMessages | undefined> {
        const ffiClients = clients.map(
            (invitee) => new CoreCrypto.#module.Invitee(invitee.id, invitee.kp)
        );
        const ffiRet: CoreCryptoFfiTypes.MemberAddedMessages = await this.#cc.add_clients_to_conversation(
            conversationId,
            ffiClients
        );

        ffiClients.forEach(c => c.free());

        if (!ffiRet) {
            return;
        }

        const ret: MemberAddedMessages = {
            welcome: ffiRet.welcome,
            message: ffiRet.message,
        };

        return ret;
    }

    async removeClientsFromConversation(
        conversationId: ConversationId,
        clientIds: Uint8Array[]
    ): Promise<Uint8Array | undefined> {
        return await this.#cc.remove_clients_from_conversation(
            conversationId,
            clientIds
        );
    }

    async leaveConversation(
        conversationId: ConversationId,
        otherClients: Uint8Array[]
    ): Promise<ConversationLeaveMessages> {
        const retFfi = await this.#cc.leave_conversation(conversationId, otherClients);
        const ret: ConversationLeaveMessages = {
            self_removal_proposal: retFfi.self_removal_proposal,
            other_clients_removal_commit: retFfi.other_clients_removal_commit,
        };
        return ret;
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

    static version(): string {
        if (!this.#module) {
            throw new Error(
                "Internal module hasn't been initialized. Please use `await CoreCrypto.init(params)`!"
            );
        }
        return this.#module.version();
    }
}
