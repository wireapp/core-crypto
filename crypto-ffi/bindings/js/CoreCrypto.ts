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
