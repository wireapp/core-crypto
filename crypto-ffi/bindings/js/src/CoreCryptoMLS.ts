import {
    MlsTransportResponseVariant,
    WasmMlsTransportResponse as MlsTransportResponseFfi,
    CommitBundle as CommitBundleFfi,
    WireIdentity,
} from "./core-crypto-ffi.js";

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

export enum CredentialType {
    /**
     * Just a KeyPair
     */
    Basic = 0x0001,
    /**
     * A certificate obtained through e2e identity enrollment process
     */
    X509 = 0x0002,
}

/**
 * Configuration object for new conversations
 */
export interface ConversationConfiguration {
    /**
     * Conversation ciphersuite
     */
    ciphersuite?: Ciphersuite;
    /**
     * List of client IDs that are allowed to be external senders of commits
     */
    externalSenders?: Uint8Array[];
    /**
     * Implementation specific configuration
     */
    custom?: CustomConfiguration;
}

/**
 * see [core_crypto::prelude::MlsWirePolicy]
 */
export enum WirePolicy {
    /**
     * Handshake messages are never encrypted
     */
    Plaintext = 0x0001,
    /**
     * Handshake messages are always encrypted
     */
    Ciphertext = 0x0002,
}

/**
 * Implementation specific configuration object for a conversation
 */
export interface CustomConfiguration {
    /**
     * Duration in seconds after which we will automatically force a self_update commit
     * Note: This isn't currently implemented
     */
    keyRotationSpan?: number;
    /**
     * Defines if handshake messages are encrypted or not
     * Note: Ciphertext is not currently supported by wire-server
     */
    wirePolicy?: WirePolicy;
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
     * MLS GroupInfo which is required for joining a group by external commit
     *
     * @readonly
     */
    groupInfo: GroupInfoBundle;
}

export function commitBundleFromFfi(
    commitBundle: CommitBundleFfi
): CommitBundle {
    return {
        commit: commitBundle.commit,
        welcome: commitBundle.welcome,
        groupInfo: {
            encryptionType: commitBundle.group_info.encryption_type,
            ratchetTreeType: commitBundle.group_info.ratchet_tree_type,
            payload: commitBundle.group_info.payload,
        },
    };
}

/**
 * Wraps a GroupInfo in order to efficiently upload it to the Delivery Service.
 * This is not part of MLS protocol but parts might be standardized at some point.
 */
export interface GroupInfoBundle {
    /**
     * see {@link GroupInfoEncryptionType}
     */
    encryptionType: GroupInfoEncryptionType;
    /**
     * see {@link RatchetTreeType}
     */
    ratchetTreeType: RatchetTreeType;
    /**
     * TLS-serialized GroupInfo
     */
    payload: Uint8Array;
}

/**
 * Informs whether the GroupInfo is confidential
 * see [core_crypto::mls::conversation::group_info::GroupInfoEncryptionType]
 */
export enum GroupInfoEncryptionType {
    /**
     * Unencrypted
     */
    Plaintext = 0x01,
    /**
     * Encrypted in a JWE (not yet implemented)
     */
    JweEncrypted = 0x02,
}

/**
 * Represents different ways of carrying the Ratchet Tree with some optimizations to save some space
 * see [core_crypto::mls::conversation::group_info::RatchetTreeType]
 */
export enum RatchetTreeType {
    /**
     * Complete GroupInfo
     */
    Full = 0x01,
    /**
     * Contains the difference since previous epoch (not yet implemented)
     */
    Delta = 0x02,
    /**
     * To define (not yet implemented)
     */
    ByRef = 0x03,
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
     * MLS Public Group State (aka Group Info) which becomes valid when the external commit
     * is accepted by the Delivery Service
     *
     * @readonly
     */
    groupInfo: GroupInfoBundle;
    /**
     * New CRL distribution points that appeared by the introduction of a new credential
     */
    crlNewDistributionPoints?: string[];
}

export interface WelcomeBundle {
    /**
     * Conversation ID
     *
     * @readonly
     */
    id: Uint8Array;
    /**
     *  New CRL Distribution of members of this group
     *
     * @readonly
     */
    crlNewDistributionPoints?: string[];
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
    /**
     * true when the decrypted message resulted in an epoch change i.e. it was a commit
     */
    hasEpochChanged: boolean;
    /**
     * Identity claims present in the sender credential
     * Only present when the credential is a x509 certificate
     * Present for all messages
     */
    identity?: WireIdentity;
    /**
     * Only set when the decrypted message is a commit.
     * Contains buffered messages for next epoch which were received before the commit creating the epoch
     * because the DS did not fan them out in order.
     */
    bufferedMessages?: BufferedDecryptedMessage[];
    /**
     * New CRL distribution points that appeared by the introduction of a new credential
     */
    crlNewDistributionPoints?: string[];
}

/**
 * Almost same as {@link DecryptedMessage} but avoids recursion
 */
export interface BufferedDecryptedMessage {
    /**
     * see {@link DecryptedMessage.message}
     */
    message?: Uint8Array;
    /**
     * see {@link DecryptedMessage.proposals}
     */
    proposals: ProposalBundle[];
    /**
     * see {@link DecryptedMessage.isActive}
     */
    isActive: boolean;
    /**
     * see {@link DecryptedMessage.commitDelay}
     */
    commitDelay?: number;
    /**
     * see {@link DecryptedMessage.senderClientId}
     */
    senderClientId?: ClientId;
    /**
     * see {@link DecryptedMessage.hasEpochChanged}
     */
    hasEpochChanged: boolean;
    /**
     * see {@link DecryptedMessage.identity}
     */
    identity?: WireIdentity;
    /**
     * see {@link DecryptedMessage.crlNewDistributionPoints}
     */
    crlNewDistributionPoints?: string[];
}

/**
 * Indicates the standalone status of a device Credential in a MLS group at a moment T.
 * This does not represent the states where a device is not using MLS or is not using end-to-end identity
 */
export enum DeviceStatus {
    /**
     * All is fine
     */
    Valid = 1,
    /**
     * The Credential's certificate is expired
     */
    Expired = 2,
    /**
     * The Credential's certificate is revoked
     */
    Revoked = 3,
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
    /**
     *  New CRL Distribution of members of this group
     *
     * @readonly
     */
    crlNewDistributionPoints?: string[];
}

/**
 * Returned by {@link MlsTransport} callbacks.
 */
export type MlsTransportResponse =
    | "success"
    | "retry"
    | {
          /**
           * The message was rejected by the delivery service and there's no recovery.
           * One special case is when the reason is `mls-client-mismatch`, where you should return Abort and then retry the whole operation.
           * For example, when adding a user to a conversation fails with `mls-client-mismatch`, then `Abort("mls-client-mismatch")`, should be returned.
           * The resulting `MessageRejected` error returned by core crypto should be caught and discarded before the operation is retried.
           */
          abort: { reason: string };
      };

export function mapTransportResponseToFfi(
    response: MlsTransportResponse
): MlsTransportResponseFfi {
    if (response === "success") {
        return new MlsTransportResponseFfi(MlsTransportResponseVariant.Success);
    }
    if (response === "retry") {
        return new MlsTransportResponseFfi(MlsTransportResponseVariant.Retry);
    }
    if (response?.abort?.reason !== undefined) {
        return new MlsTransportResponseFfi(
            MlsTransportResponseVariant.Abort,
            response.abort.reason
        );
    }
    throw new Error(
        `Invalid MlsTransportResponse returned from callback: ${response}
         Not a member of the MlsTransportResponse type.`
    );
}

/**
 * An interface that must be implemented and provided to CoreCrypto via
 * {@link CoreCrypto.provideTransport}.
 */
export interface MlsTransport {
    /**
     * This callback is called by CoreCrypto to send a commit bundle to the delivery service.
     *
     * @param commitBundle - the commit bundle
     * @returns a promise resolving to a {@link MlsTransportResponse}
     */
    sendCommitBundle: (
        commitBundle: CommitBundle
    ) => Promise<MlsTransportResponse>;

    /**
     *  This callback is called by CoreCrypto to send a regular message to the delivery service.
     * @param message
     * @returns a promise resolving to a {@link MlsTransportResponse}
     */
    sendMessage: (message: Uint8Array) => Promise<MlsTransportResponse>;
}
