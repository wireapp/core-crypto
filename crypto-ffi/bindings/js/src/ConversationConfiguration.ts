import { Ciphersuite } from "./Ciphersuite.js";
import {
    WirePolicy,
    ConversationConfiguration as ConversationConfigurationFfi,
    Ciphersuite as CiphersuiteFfi,
} from "./core-crypto-ffi.js";
import { normalizeEnum } from "./CoreCryptoE2EI.js";

export interface ConversationConfiguration {
    /**
     * The ciphersuite which should be used to encrypt this conversation.
     */
    ciphersuite?: Ciphersuite;
    /**
     * List of client IDs that are allowed to be external senders
     */
    externalSenders?: Uint8Array[];
    /**
     *  Duration in seconds after which we will automatically force a self-update commit
     *  Note: This isn't currently implemented
     */
    keyRotationSpan?: number;
    /**
     * Defines if handshake messages are encrypted or not
     * Note: encrypted handshake messages are not supported by wire-server
     */
    wirePolicy?: WirePolicy;
}

export function conversationConfigurationToFfi(
    cc: ConversationConfiguration
): ConversationConfigurationFfi {
    const ciphersuite = cc.ciphersuite
        ? normalizeEnum(CiphersuiteFfi, cc.ciphersuite)
        : undefined;
    return new ConversationConfigurationFfi(
        ciphersuite,
        cc.externalSenders,
        cc.keyRotationSpan,
        cc.wirePolicy
    );
}
