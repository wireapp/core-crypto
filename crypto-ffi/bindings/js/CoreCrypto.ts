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

export interface CoreCryptoParams {
    path: string;
    key: string;
    clientId: string;
}

export interface Invitee {
    id: string;
    kp: Uint8Array;
}

export interface CreateConversationParams {
    extraMembers: Invitee[],
    admins: string[],
    ciphersuite: string;
    keyRotationSpan: number;
}

interface __FFICreateConversationParams {
    extra_members: Invitee[],
    admins: string[],
    ciphersuite: string;
    key_rotation_span: number;
}

interface RustCoreCryptoFfi {
    create_conversation(conversationUuid: string, params: __FFICreateConversationParams): Uint8Array;
    decrypt_message(conversationUuid: string, payload: Uint8Array): Uint8Array;
    encrypt_message(conversationUuid: string, message: Uint8Array): Uint8Array;
}

export class CoreCrypto {
    #module: WebAssembly.WebAssemblyInstantiatedSource;
    #cc: RustCoreCryptoFfi;

    static async init(wasmFile: string, params: CoreCryptoParams): Promise<CoreCrypto> {
        const wasmModule = await WebAssembly.instantiateStreaming(fetch(wasmFile), {})
        const self = new CoreCrypto({ wasmModule, ...params });
        return self;
    }

    constructor({ wasmModule, path, key, clientId }: CoreCryptoParams & {
        wasmModule: WebAssembly.WebAssemblyInstantiatedSource
    }) {
        this.#module = wasmModule;
        this.#cc = (this.#module.instance.exports.init_with_path_and_key as CallableFunction)(path, key, clientId);
    }

    createConversation(conversationUuid: string, { extraMembers, admins, ciphersuite, keyRotationSpan }: CreateConversationParams) {
        return this.#cc.create_conversation(conversationUuid, {
            extra_members: extraMembers,
            admins,
            ciphersuite,
            key_rotation_span: keyRotationSpan
        });
    }

    decryptMessage(conversationUuid: string, payload: Uint8Array): Uint8Array {
        return this.#cc.decrypt_message(conversationUuid, payload);
    }

    encryptMessage(conversationUuid: string, message: Uint8Array): Uint8Array {
        return this.#cc.encrypt_message(conversationUuid, message);
    }

    version(): string {
        return (this.#module.instance.exports.version as CallableFunction)();
    }
}
