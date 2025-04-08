import { Ciphersuite } from "./Ciphersuite.js";
import {
    Ciphersuite as CiphersuiteFfi,
    ConversationConfiguration as ConversationConfigurationFfi,
    WirePolicy,
} from "./core-crypto-ffi.js";

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
        ? new CiphersuiteFfi(cc.ciphersuite)
        : null;
    return new ConversationConfigurationFfi(
        ciphersuite,
        cc.externalSenders,
        cc.keyRotationSpan,
        cc.wirePolicy
    );
}
