import { safeBigintToNumber } from "./Conversions.js";
import {
    BufferedDecryptedMessage as BufferedDecryptedMessageFfi,
    CommitBundle as CommitBundleFfi,
    CredentialType,
    DecryptedMessage as DecryptedMessageFfi,
    DeviceStatus,
    MlsGroupInfoEncryptionType as GroupInfoEncryptionType,
    MlsRatchetTreeType as RatchetTreeType,
    MlsTransport as MlsTransportFfi,
    MlsTransportResponse as MlsTransportResponseFfi,
    MlsTransportResponseVariant,
    ProposalBundle as ProposalBundleFfi,
    WelcomeBundle,
    WireIdentity,
    WirePolicy,
} from "./core-crypto-ffi.js";

export {
    CredentialType,
    DeviceStatus,
    GroupInfoEncryptionType,
    RatchetTreeType,
    WelcomeBundle,
    WirePolicy,
};

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

function commitBundleFromFfi(commitBundle: CommitBundleFfi): CommitBundle {
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

export function decryptedMessageFromFfi(
    m: DecryptedMessageFfi
): DecryptedMessage {
    return {
        bufferedMessages:
            m.bufferedMessages?.map((msg) =>
                bufferedDecryptedMessageFromFfi(msg)
            ) ?? undefined,
        ...bufferedDecryptedMessageFromFfi(m),
    };
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

export function bufferedDecryptedMessageFromFfi(
    m: BufferedDecryptedMessageFfi
): BufferedDecryptedMessage {
    return {
        message: m.message,
        proposals: m.proposals.map((proposal) =>
            proposalBundleFromFfi(proposal)
        ),
        isActive: m.isActive,
        commitDelay: m.commitDelay
            ? safeBigintToNumber(m.commitDelay)
            : undefined,
        senderClientId: m.senderClientId?.as_bytes(),
        hasEpochChanged: m.hasEpochChanged,
        identity: m.identity,
        crlNewDistributionPoints: m.crlNewDistributionPoints.as_strings(),
    };
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
     * Unique identifier of a proposal.
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

export function proposalBundleFromFfi(p: ProposalBundleFfi): ProposalBundle {
    return {
        proposal: p.proposal,
        proposalRef: p.proposal_ref,
        crlNewDistributionPoints: p.crl_new_distribution_points,
    };
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
           */
          abort: { reason: string };
      };

function mapTransportResponseToFfi(
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

/**
 * This shim wraps an `MlsTransport` according to our public API and implements the inner FFI transport API,
 * mapping appropriately between the two.
 */
class MlsTransportFfiShim {
    private inner: MlsTransport;

    constructor(inner: MlsTransport) {
        this.inner = inner;
    }

    async sendCommitBundle(
        commitBundle: CommitBundleFfi
    ): Promise<MlsTransportResponseFfi> {
        const cb = commitBundleFromFfi(commitBundle);
        const response = await this.inner.sendCommitBundle(cb);
        return mapTransportResponseToFfi(response);
    }

    async sendMessage(message: Uint8Array): Promise<MlsTransportResponseFfi> {
        const response = await this.inner.sendMessage(message);
        return mapTransportResponseToFfi(response);
    }
}

export function mlsTransportToFfi(mlsTransport: MlsTransport): MlsTransportFfi {
    const shim = new MlsTransportFfiShim(mlsTransport);
    return new MlsTransportFfi(shim, shim.sendCommitBundle, shim.sendMessage);
}
