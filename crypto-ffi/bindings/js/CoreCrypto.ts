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

// WIP

type Buffer = Uint8Array;
export type ConversationId = Buffer;

type RustCoreCryptoFfiInstance = any;

export interface CoreCryptoParams {
    path: string;
    key: string;
    clientId: string;
}

export interface Invitee {
    id: string;
    kp: Buffer;
}

export interface MemberAddedMessages {
    welcome: Buffer;
    message: Buffer;
}

export interface ConversationConfiguration {
    extraMembers?: Invitee[],
    admins?: string[],
    ciphersuite?: string;
    keyRotationSpan?: number;
}

interface __FFIConversationConfiguration {
    extra_members: Invitee[],
    admins: string[],
    ciphersuite: string;
    key_rotation_span: number;
}

interface RustCoreCryptoFfi {
    cc_create_conversation(ptr: RustCoreCryptoFfiInstance, conversationId: string, params: __FFIConversationConfiguration): Buffer;
    cc_decrypt_message(ptr: RustCoreCryptoFfiInstance, conversationId: string, payload: Buffer): Buffer;
    cc_encrypt_message(ptr: RustCoreCryptoFfiInstance, conversationId: string, message: Buffer): Buffer;
    cc_process_welcome_message(ptr: RustCoreCryptoFfiInstance, welcomeMessage: Buffer, config: __FFIConversationConfiguration): ConversationId;
    cc_client_public_key(ptr: RustCoreCryptoFfiInstance,): Buffer;
    cc_client_keypackages(ptr: RustCoreCryptoFfiInstance, amountRequested: number): Array<Buffer>;
    cc_add_clients_to_conversation(ptr: RustCoreCryptoFfiInstance, conversationId: ConversationId, clients: Invitee[]): MemberAddedMessages | null;
    cc_remove_clients_from_conversation(ptr: RustCoreCryptoFfiInstance, conversationId: ConversationId, clients: Invitee[]): Buffer | null;
    cc_conversation_exists(ptr: RustCoreCryptoFfiInstance, conversationId: ConversationId): boolean;
    cc_version(): string;
}

const stubFfiModule = (): WebAssembly.WebAssemblyInstantiatedSource => ({
    module: null,
    instance: {
        exports: {
            cc_create_conversation(ptr: RustCoreCryptoFfiInstance, conversationId: string, params: __FFIConversationConfiguration): Buffer {
                return new Uint8Array();
            },
            cc_decrypt_message(ptr: RustCoreCryptoFfiInstance, conversationId: string, payload: Buffer): Buffer {
                return new Uint8Array();
            },
            cc_encrypt_message(ptr: RustCoreCryptoFfiInstance, conversationId: string, message: Buffer): Buffer {
                return new Uint8Array();
            },
            cc_process_welcome_message(ptr: RustCoreCryptoFfiInstance, welcomeMessage: Buffer, config: __FFIConversationConfiguration): ConversationId {
                return new Uint8Array();
            },
            cc_client_public_key(ptr: RustCoreCryptoFfiInstance,): Buffer {
                return new Uint8Array();
            },
            cc_client_keypackages(ptr: RustCoreCryptoFfiInstance, amountRequested: number): Array<Buffer> {
                return [];
            },
            cc_add_clients_to_conversation(ptr: RustCoreCryptoFfiInstance, conversationId: ConversationId, clients: Invitee[]): MemberAddedMessages | null {
                return null;
            },
            cc_remove_clients_from_conversation(ptr: RustCoreCryptoFfiInstance, conversationId: ConversationId, clients: Invitee[]): Buffer | null {
                return null;
            },
            cc_conversation_exists(ptr: RustCoreCryptoFfiInstance, conversationId: ConversationId): boolean {
                return false;
            },
            cc_version(): string {
                return "0.2.0-stub";
            }
        }
    }
});

export class CoreCrypto {
    #module: WebAssembly.WebAssemblyInstantiatedSource;
    #ccFFI: RustCoreCryptoFfi;
    #cc: any;

    static async init(wasmFile: string, params: CoreCryptoParams): Promise<CoreCrypto> {
        const wasmModule = await WebAssembly.instantiateStreaming(fetch(wasmFile), {})
        const self = new CoreCrypto({ wasmModule, ...params });
        return self;
    }

    static async initStubbed(_wasmFile: string, params: CoreCryptoParams): Promise<CoreCrypto> {
        const wasmModule = stubFfiModule();
        const self = new CoreCrypto({ wasmModule, ...params });
        return self;
    }

    constructor({ wasmModule, path, key, clientId }: CoreCryptoParams & {
        wasmModule: WebAssembly.WebAssemblyInstantiatedSource
    }) {
        this.#module = wasmModule;
        this.#cc = (this.#module.instance.exports.init_with_path_and_key as CallableFunction)(path, key, clientId);
        this.#ccFFI = this.#module.instance.exports as any as RustCoreCryptoFfi;
    }

    createConversation(conversationId: string, { extraMembers, admins, ciphersuite, keyRotationSpan }: ConversationConfiguration) {
        return this.#ccFFI.cc_create_conversation(this.#cc, conversationId, {
            extra_members: extraMembers ?? [],
            admins: admins ?? [],
            ciphersuite,
            key_rotation_span: keyRotationSpan,
        });
    }

    decryptMessage(conversationId: string, payload: Buffer): Buffer {
        return this.#ccFFI.cc_decrypt_message(this.#cc, conversationId, payload);
    }

    encryptMessage(conversationId: string, message: Buffer): Buffer {
        return this.#ccFFI.cc_encrypt_message(this.#cc, conversationId, message);
    }

    processWelcomeMessage(welcomeMessage: Buffer, { extraMembers, admins, ciphersuite, keyRotationSpan }: ConversationConfiguration): ConversationId {
        return this.#ccFFI.cc_process_welcome_message(this.#cc, welcomeMessage, {
            extra_members: extraMembers ?? [],
            admins: admins ?? [],
            ciphersuite,
            key_rotation_span: keyRotationSpan,
        });
    }

    clientPublicKey(): Buffer {
        return this.#ccFFI.cc_client_public_key(this.#cc,);
    }

    clientKeypackages(amountRequested: number): Array<Buffer> {
        return this.#ccFFI.cc_client_keypackages(this.#cc, amountRequested);
    }

    addClientsToConverastion(conversationId: ConversationId, clients: Invitee[]): MemberAddedMessages | null {
        return this.#ccFFI.cc_add_clients_to_conversation(this.#cc, conversationId, clients);
    }

    removeClientsFromConversation(conversationId: ConversationId, clients: Invitee[]): Buffer | null {
        return this.#ccFFI.cc_remove_clients_from_conversation(this.#cc, conversationId, clients);
    }

    conversationExists(conversationId: ConversationId): boolean {
        return this.#ccFFI.cc_conversation_exists(this.#cc, conversationId);
    }

    version(): string {
        return (this.#module.instance.exports.cc_version as CallableFunction)();
    }
}
