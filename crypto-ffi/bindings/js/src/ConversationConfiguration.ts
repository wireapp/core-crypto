import {
    Ciphersuite,
    ConversationConfiguration as ConversationConfigurationFfi,
    CustomConfiguration,
    WirePolicy,
    ExternalSenderKey,
} from "./index.web";

export interface ConversationConfiguration {
    /**
     * The ciphersuite which should be used to encrypt this conversation.
     */
    ciphersuite?: Ciphersuite;
    /**
     * List of client IDs that are allowed to be external senders
     */
    externalSenders?: ExternalSenderKey[];
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
    return ConversationConfigurationFfi.create({
        ciphersuite: cc.ciphersuite,
        externalSenders: cc.externalSenders || [],
        custom: CustomConfiguration.create({
            keyRotationSpan: cc.keyRotationSpan,
            wirePolicy: cc.wirePolicy
        })
    }
    );
}
