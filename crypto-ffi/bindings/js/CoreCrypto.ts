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

import * as CoreCryptoFfiTypes from "./wasm/core-crypto-ffi.d.js";
import initWasm, {
    AcmeChallenge,
    ConversationConfiguration as ConversationConfigurationFfi,
    CoreCrypto as CoreCryptoFfi,
    CoreCryptoContext as CoreCryptoContextFfi,
    CoreCryptoWasmCallbacks,
    CoreCryptoWasmLogger,
    CustomConfiguration as CustomConfigurationFfi,
    E2eiDumpedPkiEnv,
    NewAcmeAuthz,
    NewAcmeOrder,
} from "./wasm";

import CoreCryptoContext from "./CoreCryptoContext";

// re-exports
export {
    NewAcmeOrder,
    NewAcmeAuthz,
    AcmeChallenge,
    E2eiDumpedPkiEnv,
    ConversationConfigurationFfi,
    CoreCryptoContext,
    CoreCryptoContextFfi,
    CustomConfigurationFfi,
};

export interface CoreCryptoRichError {
    message: string;
    error_name?: string;
    error_stack?: string[];
    proteus_error_code?: number;
}

/**
 * Error wrapper that takes care of extracting rich error details across the FFI (through JSON parsing)
 *
 * Whenever you're supposed to get this class (that extends `Error`) you might end up with a base `Error`
 * in case the parsing of the message structure fails. This is unlikely but the case is still covered and fall backs automatically.
 * More information will be found in the base `Error.cause` to inform you why the parsing has failed.
 *
 * Please note that in this case the extra properties will not be available.
 */
export class CoreCryptoError extends Error {
    errorStack: string[];
    proteusErrorCode: number | null;

    private constructor(richError: CoreCryptoRichError, ...params: unknown[]) {
        // @ts-expect-error TS2556: A spread argument must either have a tuple type or be passed to a rest parameter.
        super(richError.message, ...params);
        Object.setPrototypeOf(this, new.target.prototype);

        if (richError.error_name) {
            this.name = richError.error_name;
        }
        if (richError.error_stack) {
            this.errorStack = richError.error_stack;
        } else {
            this.errorStack = [];
        }
        if (richError.proteus_error_code) {
            this.proteusErrorCode = richError.proteus_error_code;
        } else {
            this.proteusErrorCode = null;
        }
    }

    private static fallback(msg: string, ...params: unknown[]): Error {
        console.warn(
            `Cannot build CoreCryptoError, falling back to standard Error! ctx: ${msg}`
        );
        // @ts-expect-error TS2556: A spread argument must either have a tuple type or be passed to a rest parameter.
        return new Error(msg, ...params);
    }

    static build(msg: string, ...params: unknown[]): CoreCryptoError | Error {
        try {
            const richError: CoreCryptoRichError = JSON.parse(msg);
            return new this(richError, ...params);
        } catch (cause) {
            return this.fallback(msg, ...params);
        }
    }

    static fromStdError(e: Error): CoreCryptoError | Error {
        const opts = {
            cause: e.cause || undefined,
            stack: e.stack || undefined,
        };

        return this.build(e.message, opts);
    }

    static async asyncMapErr<T>(p: Promise<T>): Promise<T> {
        const mappedErrorPromise = p.catch((e: Error | CoreCryptoError) => {
            if (e instanceof CoreCryptoError) {
                throw e;
            } else {
                throw this.fromStdError(e);
            }
        });

        return await mappedErrorPromise;
    }
}

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
 * Data shape for proteusNewPrekeyAuto() call returns.
 */
export interface ProteusAutoPrekeyBundle {
    /**
     * Proteus PreKey id
     *
     * @readonly
     */
    id: number;
    /**
     * CBOR-serialized Proteus PreKeyBundle
     *
     * @readonly
     */
    pkb: Uint8Array;
}

/**
 * Data shape for the returned MLS commit & welcome message tuple upon adding clients to a conversation
 */
export interface MemberAddedMessages {
    /**
     * TLS-serialized MLS Commit that needs to be fanned out to other (existing) members of the conversation
     *
     * @readonly
     */
    commit: Uint8Array;
    /**
     * TLS-serialized MLS Welcome message that needs to be fanned out to the clients newly added to the conversation
     *
     * @readonly
     */
    welcome: Uint8Array;
    /**
     * MLS GroupInfo which is required for joining a group by external commit
     *
     * @readonly
     */
    groupInfo: GroupInfoBundle;
    /**
     * New CRL distribution points that appeared by the introduction of a new credential
     */
    crlNewDistributionPoints?: string[];
}

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

/**
 * Result returned after rotating the Credential of the current client in all the local conversations
 */
export interface RotateBundle {
    /**
     * An Update commit for each conversation
     *
     * @readonly
     */
    commits: Map<string, CommitBundle>;
    /**
     * Fresh KeyPackages with the new Credential
     *
     * @readonly
     */
    newKeyPackages: Uint8Array[];
    /**
     * All the now deprecated KeyPackages. Once deleted remotely, delete them locally with {@link CoreCrypto.deleteKeyPackages}
     *
     * @readonly
     */
    keyPackageRefsToRemove: Uint8Array[];
    /**
     * New CRL distribution points that appeared by the introduction of a new credential
     */
    crlNewDistributionPoints?: string[];
}

/**
 * Params for CoreCrypto deferred initialization
 * Please note that the `entropySeed` parameter MUST be exactly 32 bytes
 */
export interface CoreCryptoDeferredParams {
    /**
     * Name of the IndexedDB database
     */
    databaseName: string;
    /**
     * Encryption master key
     * This should be appropriately stored in a secure location (i.e. WebCrypto private key storage)
     */
    key: string;
    /**
     * External PRNG entropy pool seed.
     * This **must** be exactly 32 bytes
     */
    entropySeed?: Uint8Array;
    /**
     * .wasm file path, this will be useful in case your bundling system likes to relocate files (i.e. what webpack does)
     */
    wasmFilePath?: string;
}

/**
 * Params for CoreCrypto initialization
 * Please note that the `entropySeed` parameter MUST be exactly 32 bytes
 */
export interface CoreCryptoParams extends CoreCryptoDeferredParams {
    /**
     * MLS Client ID.
     * This should stay consistent as it will be verified against the stored signature & identity to validate the persisted credential
     */
    clientId: ClientId;
    /**
     * All the ciphersuites this MLS client can support
     */
    ciphersuites: Ciphersuite[];
    /**
     * Number of initial KeyPackage to create when initializing the client
     */
    nbKeyPackage?: number;
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
     * MLS Public Group State (aka Group Info) which becomes valid when the external commit is accepted by the Delivery Service
     * with {@link CoreCrypto.mergePendingGroupFromExternalCommit}
     *
     * @readonly
     */
    groupInfo: GroupInfoBundle;
    /**
     * New CRL distribution points that appeared by the introduction of a new credential
     */
    crlNewDistributionPoints?: string[];
}

/**
 *  Supporting struct for CRL registration result
 */
export interface CRLRegistration {
    /**
     * Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
     *
     * @readonly
     */
    dirty: boolean;
    /**
     * Optional expiration timestamp
     *
     * @readonly
     */
    expiration?: number;
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
 * Represents the identity claims identifying a client
 * Those claims are verifiable by any member in the group
 */
export interface WireIdentity {
    /**
     * Unique client identifier
     */
    clientId: string;
    /**
     * Status of the Credential at the moment T when this object is created
     */
    status: DeviceStatus;
    /**
     * MLS thumbprint
     */
    thumbprint: string;
    /**
     * Indicates whether the credential is Basic or X509
     */
    credentialType: CredentialType;
    /**
     * In case {@link credentialType} is {@link CredentialType.X509} this is populated
     */
    x509Identity?: X509Identity;
}

/**
 * Represents the parts of {@link WireIdentity} that are specific to a X509 certificate (and not a Basic one).
 */
export interface X509Identity {
    /**
     * User handle e.g. `john_wire`
     */
    handle: string;
    /**
     * Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
     */
    displayName: string;
    /**
     * DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
     */
    domain: string;
    /**
     * X509 certificate identifying this client in the MLS group ; PEM encoded
     */
    certificate: string;
    /**
     * X509 certificate serial number
     */
    serialNumber: string;
    /**
     * X509 certificate not before as Unix timestamp
     */
    notBefore: bigint;
    /**
     * X509 certificate not after as Unix timestamp
     */
    notAfter: bigint;
}

export function normalizeEnum<T>(enumType: T, value: number): T[keyof T] {
    const enumAsString = enumType[value as unknown as keyof T];
    const enumAsDiscriminant = enumType[enumAsString as unknown as keyof T];
    return enumAsDiscriminant;
}

export const mapWireIdentity = (
    ffiIdentity?: CoreCryptoFfiTypes.WireIdentity
): WireIdentity | undefined => {
    if (!ffiIdentity) {
        return undefined;
    }
    return {
        clientId: ffiIdentity.client_id,
        status: normalizeEnum(DeviceStatus, ffiIdentity.status),
        thumbprint: ffiIdentity.thumbprint,
        credentialType: normalizeEnum(
            CredentialType,
            ffiIdentity.credential_type
        ),
        x509Identity: mapX509Identity(ffiIdentity.x509_identity),
    };
};

const mapX509Identity = (
    ffiIdentity?: CoreCryptoFfiTypes.X509Identity
): X509Identity | undefined => {
    if (!ffiIdentity) {
        return undefined;
    }
    return {
        handle: ffiIdentity.handle,
        displayName: ffiIdentity.display_name,
        domain: ffiIdentity.domain,
        certificate: ffiIdentity.certificate,
        serialNumber: ffiIdentity.serial_number,
        notBefore: ffiIdentity.not_before,
        notAfter: ffiIdentity.not_after,
    };
};

export interface AcmeDirectory {
    /**
     * URL for fetching a new nonce. Use this only for creating a new account.
     */
    newNonce: string;
    /**
     * URL for creating a new account.
     */
    newAccount: string;
    /**
     * URL for creating a new order.
     */
    newOrder: string;
    /**
     * Revocation URL
     */
    revokeCert: string;
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
 * MLS Proposal type
 */
export enum ProposalType {
    /**
     * This allows to propose the addition of other clients to the MLS group/conversation
     */
    Add,
    /**
     * This allows to propose the removal of clients from the MLS group/conversation
     */
    Remove,
    /**
     * This allows to propose to update the client keying material (i.e. keypackage rotation) and the group root key
     */
    Update,
}

/**
 * Common arguments for proposals
 */
export interface ProposalArgs {
    /**
     * Conversation ID that is targeted by the proposal
     */
    conversationId: ConversationId;
}

/**
 * Arguments for a proposal of type `Add`
 */
export interface AddProposalArgs extends ProposalArgs {
    /**
     * TLS-serialized MLS KeyPackage to be added
     */
    kp: Uint8Array;
}

/**
 * Arguments for a proposal of type `Remove`
 */
export interface RemoveProposalArgs extends ProposalArgs {
    /**
     * Client ID to be removed from the conversation
     */
    clientId: ClientId;
}

/**
 * MLS External Proposal type
 */
export enum ExternalProposalType {
    /**
     * This allows to propose the addition of other clients to the MLS group/conversation
     */
    Add,
}

export interface ExternalProposalArgs {
    /**
     * Conversation ID that is targeted by the external proposal
     */
    conversationId: ConversationId;
    /**
     * MLS Group epoch for the external proposal.
     * This needs to be the current epoch of the group or this proposal **will** be rejected
     */
    epoch: number;
}

export interface ExternalAddProposalArgs extends ExternalProposalArgs {
    /**
     * {@link Ciphersuite} to propose to join the MLS group with.
     */
    ciphersuite: Ciphersuite;
    /**
     * Fails when it is {@link CredentialType.X509} and no Credential has been created
     * for it beforehand with {@link CoreCrypto.e2eiMlsInit} or variants.
     */
    credentialType: CredentialType;
}

export interface CoreCryptoCallbacks {
    /**
     * This callback is called by CoreCrypto to know whether a given clientId is authorized to "write"
     * in the given conversationId. Think of it as a "isAdmin" callback conceptually
     *
     * This callback exists because there are many business cases where CoreCrypto doesn't have enough knowledge
     * (such as what can exist on a backend) to inform the decision
     *
     * @param conversationId - id of the group/conversation
     * @param clientId - id of the client performing an operation requiring authorization
     * @returns whether the user is authorized by the logic layer to perform the operation
     */
    authorize: (
        conversationId: Uint8Array,
        clientId: Uint8Array
    ) => Promise<boolean>;

    /**
     * A mix between {@link authorize} and {@link clientIsExistingGroupUser}. We currently use this callback to verify
     * external commits to join a group ; in such case, the client has to:
     * * first, belong to a user which is already in the MLS group (similar to {@link clientIsExistingGroupUser})
     * * then, this user should be authorized to "write" in the given conversation (similar to {@link authorize})
     *
     * @param conversationId - id of the group/conversation
     * @param externalClientId - id of the client performing an operation requiring authorization
     * @param existingClients - all the clients currently within the MLS group
     * @returns true if the external client is authorized to write to the conversation
     */
    userAuthorize: (
        conversationId: Uint8Array,
        externalClientId: Uint8Array,
        existingClients: Uint8Array[]
    ) => Promise<boolean>;

    /**
     * Callback to ensure that the given `clientId` belongs to one of the provided `existingClients`
     * This basically allows to defer the client ID parsing logic to the caller - because CoreCrypto is oblivious to such things
     *
     * @param conversationId - id of the group/conversation
     * @param clientId - id of a client
     * @param existingClients - all the clients currently within the MLS group
     */
    clientIsExistingGroupUser: (
        conversationId: Uint8Array,
        clientId: Uint8Array,
        existingClients: Uint8Array[],
        parent_conversation_clients?: Uint8Array[]
    ) => Promise<boolean>;
}

/**
 * An interface to register a logger in CoreCrypto
 **/
export interface CoreCryptoLogger {
    /**
     * This method will be called by Core Crypto to log messages. It is up to the implementer to decide how to handle the message and where to actually log it.
     * @param level - the level of the logged message. it will also be present in the json message
     * @param message - log message
     * @param context - additional context captured when the log was made.
     **/
    log: (level: CoreCryptoLogLevel, message: string, context: string) => void;
}

/**
 * Defines the maximum log level for the logs from Core Crypto
 **/
export enum CoreCryptoLogLevel {
    Off = 1,
    Trace = 2,
    Debug = 3,
    Info = 4,
    Warn = 5,
    Error = 6,
}

/**
 * Initializes the global logger for Core Crypto and registers the callback.
 *
 * **NOTE:** you must call this after `await CoreCrypto.init(params)` or `await CoreCrypto.deferredInit(params)`.
 *
 * @deprecated use {@link CoreCrypto.setLogger} instead.
 *
 * @param logger - the interface to be called when something is going to be logged
 * @param level - the max level that should be logged
 **/
export function initLogger(
    logger: CoreCryptoLogger,
    level: CoreCryptoLogLevel,
    ctx: unknown = null
): void {
    const wasmLogger = new CoreCryptoWasmLogger(logger.log, ctx);
    CoreCrypto.setLogger(wasmLogger);
    CoreCrypto.setMaxLogLevel(level);
}

/**
 * Initializes the global logger for Core Crypto and registers the callback.
 *
 * **NOTE:** you must call this after `await CoreCrypto.init(params)` or `await CoreCrypto.deferredInit(params)`.
 *
 * @param logger - the interface to be called when something is going to be logged
 **/
export function setLogger(logger: CoreCryptoLogger, ctx: unknown = null): void {
    const wasmLogger = new CoreCryptoWasmLogger(logger.log, ctx);
    CoreCrypto.setLogger(wasmLogger);
}

/**
 * Sets maximum log level for logs forwarded to the logger, defaults to `Warn`.
 *
 * @param level - the max level that should be logged
 */
export function setMaxLogLevel(level: CoreCryptoLogLevel): void {
    CoreCrypto.setMaxLogLevel(level);
}

/**
 * Wrapper for the WASM-compiled version of CoreCrypto
 */
export class CoreCrypto {
    /** @hidden */
    static #module: typeof CoreCryptoFfiTypes;
    /** @hidden */
    #cc: CoreCryptoFfiTypes.CoreCrypto;

    /**
     * Should only be used internally
     */
    inner(): unknown {
        return this.#cc as CoreCryptoFfiTypes.CoreCrypto;
    }

    /** @hidden */
    static #assertModuleLoaded() {
        if (!this.#module) {
            throw new Error(
                "Internal module hasn't been initialized. Please use `await CoreCrypto.init(params)` or `await CoreCrypto.deferredInit(params)` !"
            );
        }
    }

    /** @hidden */
    static async #loadModule(wasmFilePath?: string) {
        if (!this.#module) {
            this.#module = (await initWasm(
                wasmFilePath
            )) as unknown as typeof CoreCryptoFfiTypes;
        }
    }

    static setLogger(logger: CoreCryptoWasmLogger) {
        this.#assertModuleLoaded();
        CoreCryptoFfi.set_logger(logger);
    }

    static setMaxLogLevel(level: CoreCryptoLogLevel) {
        this.#assertModuleLoaded();
        CoreCryptoFfi.set_max_log_level(level);
    }

    /**
     * This is your entrypoint to initialize {@link CoreCrypto}!
     *
     * @param params - {@link CoreCryptoParams}
     *
     * @example
     * ## Simple init
     * ```ts
     * const cc = await CoreCrypto.init({ databaseName: "test", key: "test", clientId: "test" });
     * // Do the rest with `cc`
     * ```
     *
     * ## Custom Entropy seed init & wasm file location
     * ```ts
     * // FYI, this is the IETF test vector #1
     * const entropySeed = Uint32Array.from([
     *   0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653,
     *   0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b,
     *   0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8,
     *   0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2,
     * ]);
     *
     * const wasmFilePath = "/long/complicated/path/on/webserver/whatever.wasm";
     *
     * const cc = await CoreCrypto.init({
     *   databaseName: "test",
     *   key: "test",
     *   clientId: "test",
     *   entropySeed,
     *   wasmFilePath,
     * });
     * ````
     */
    static async init({
        databaseName,
        key,
        clientId,
        wasmFilePath,
        ciphersuites,
        entropySeed,
        nbKeyPackage,
    }: CoreCryptoParams): Promise<CoreCrypto> {
        await this.#loadModule(wasmFilePath);

        const cs = ciphersuites.map((cs) => cs.valueOf());
        const cc = await CoreCryptoError.asyncMapErr(
            CoreCryptoFfi._internal_new(
                databaseName,
                key,
                clientId,
                Uint16Array.of(...cs),
                entropySeed,
                nbKeyPackage
            )
        );
        return new this(cc);
    }

    /**
     * Almost identical to {@link CoreCrypto.init} but allows a 2 phase initialization of MLS.
     * First, calling this will set up the keystore and will allow generating proteus prekeys.
     * Then, those keys can be traded for a clientId.
     * Use this clientId to initialize MLS with {@link CoreCrypto.mlsInit}.
     * @param params - {@link CoreCryptoDeferredParams}
     */
    static async deferredInit({
        databaseName,
        key,
        entropySeed,
        wasmFilePath,
    }: CoreCryptoDeferredParams): Promise<CoreCrypto> {
        await this.#loadModule(wasmFilePath);

        const cc = await CoreCryptoError.asyncMapErr(
            CoreCryptoFfi.deferred_init(databaseName, key, entropySeed)
        );
        return new this(cc);
    }

    /**
     * Starts a new transaction in Core Crypto. If the callback succeeds, it will be committed,
     * otherwise, every operation performed with the context will be discarded.
     *
     * @param callback - The callback to execute within the transaction
     *
     * @returns the result of the callback will be returned from this call
     */
    async transaction<R>(
        callback: (ctx: CoreCryptoContext) => Promise<R>
    ): Promise<R> {
        let result!: R;
        let error: CoreCryptoError | null = null;
        try {
            await this.#cc.transaction({
                execute: async (ctx: CoreCryptoFfiTypes.CoreCryptoContext) => {
                    try {
                        result = await callback(
                            CoreCryptoContext.fromFfiContext(ctx)
                        );
                    } catch (e) {
                        // We want to catch the error before it gets wrapped by core crypto.
                        if (e instanceof CoreCryptoError) {
                            error = e as CoreCryptoError;
                        } else {
                            error = CoreCryptoError.fromStdError(
                                e as Error
                            ) as CoreCryptoError;
                        }
                        // This is to tell core crypto that there was an error inside the transaction.
                        throw error;
                    }
                },
            });
            // Catch the wrapped error, which we don't need, because we caught the original error above.
        } catch (_) {}
        if (error !== null) {
            throw error;
        }
        return result;
    }

    /**
     * See {@link CoreCryptoContext.mlsInit}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.mlsInit} instead.
     */
    async mlsInit(
        clientId: ClientId,
        ciphersuites: Ciphersuite[],
        nbKeyPackage?: number
    ): Promise<void> {
        return await this.transaction(
            async (ctx) =>
                await ctx.mlsInit(clientId, ciphersuites, nbKeyPackage)
        );
    }

    /**
     * See {@link CoreCryptoContext.mlsGenerateKeypair}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.mlsGenerateKeypair} instead.
     */
    async mlsGenerateKeypair(
        ciphersuites: Ciphersuite[]
    ): Promise<Uint8Array[]> {
        return await this.transaction(
            async (ctx) => await ctx.mlsGenerateKeypair(ciphersuites)
        );
    }

    /**
     * See {@link CoreCryptoContext.mlsInitWithClientId}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.mlsInitWithClientId} instead.
     */
    async mlsInitWithClientId(
        clientId: ClientId,
        signaturePublicKeys: Uint8Array[],
        ciphersuites: Ciphersuite[]
    ): Promise<void> {
        return await this.transaction(
            async (ctx) =>
                await ctx.mlsInitWithClientId(
                    clientId,
                    signaturePublicKeys,
                    ciphersuites
                )
        );
    }

    /** @hidden */
    private constructor(cc: CoreCryptoFfiTypes.CoreCrypto) {
        this.#cc = cc;
    }

    /**
     * If this returns `true` you **cannot** call {@link CoreCrypto.wipe} or {@link CoreCrypto.close} as they will produce an error because of the
     * outstanding references that were detected.
     *
     * @returns the count of strong refs for this CoreCrypto instance
     */
    isLocked(): boolean {
        return this.#cc.has_outstanding_refs();
    }

    /**
     * Wipes the {@link CoreCrypto} backing storage (i.e. {@link https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API | IndexedDB} database)
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be useable after a call to this method, but there's no way to express this requirement in TypeScript so you'll get errors instead!
     */
    async wipe() {
        await CoreCryptoError.asyncMapErr(this.#cc.wipe());
    }

    /**
     * Closes this {@link CoreCrypto} instance and deallocates all loaded resources
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be usable after a call to this method, but there's no way to express this requirement in TypeScript, so you'll get errors instead!
     */
    async close() {
        await CoreCryptoError.asyncMapErr(this.#cc.close());
    }

    /**
     * Registers the callbacks for CoreCrypto to use in order to gain additional information
     *
     * @param callbacks - Any interface following the {@link CoreCryptoCallbacks} interface
     */
    async registerCallbacks(
        callbacks: CoreCryptoCallbacks,
        ctx: unknown = null
    ): Promise<void> {
        try {
            const wasmCallbacks = new CoreCryptoWasmCallbacks(
                callbacks.authorize,
                callbacks.userAuthorize,
                callbacks.clientIsExistingGroupUser,
                ctx
            );
            await this.#cc.set_callbacks(wasmCallbacks);
        } catch (e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * See {@link CoreCryptoContext.conversationExists}.
     */
    async conversationExists(conversationId: ConversationId): Promise<boolean> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.conversation_exists(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.markConversationAsChildOf}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.markConversationAsChildOf} instead.
     */
    async markConversationAsChildOf(
        childId: ConversationId,
        parentId: ConversationId
    ): Promise<void> {
        return await this.transaction(
            async (ctx) =>
                await ctx.markConversationAsChildOf(childId, parentId)
        );
    }

    /**
     * See {@link CoreCryptoContext.conversationEpoch}.
     *
     * @returns the epoch of the conversation
     *
     * @example
     * ```ts
     *  const cc = await CoreCrypto.init({ databaseName: "test", key: "test", clientId: "test" });
     *  const encoder = new TextEncoder();
     *  console.log(await cc.conversationEpoch(encoder.encode("my super chat")))
     * ```
     */
    async conversationEpoch(conversationId: ConversationId): Promise<number> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.conversation_epoch(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.conversationCiphersuite}.
     *
     * @returns the ciphersuite of the conversation
     */
    async conversationCiphersuite(
        conversationId: ConversationId
    ): Promise<Ciphersuite> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.conversation_ciphersuite(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.wipeConversation}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.wipeConversation} instead.
     */
    async wipeConversation(conversationId: ConversationId): Promise<void> {
        return await this.transaction(
            async (ctx) => await ctx.wipeConversation(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.createConversation}.
     *
     * @deprecated Create a transaction with {@link transaction}
     * and use {@link CoreCryptoContext.createConversation} instead.
     */
    async createConversation(
        conversationId: ConversationId,
        creatorCredentialType: CredentialType,
        configuration: ConversationConfiguration = {}
    ) {
        return await this.transaction(
            async (ctx) =>
                await ctx.createConversation(
                    conversationId,
                    creatorCredentialType,
                    configuration
                )
        );
    }

    /**
     * See {@link CoreCryptoContext.decryptMessage}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.decryptMessage} instead.
     */
    async decryptMessage(
        conversationId: ConversationId,
        payload: Uint8Array
    ): Promise<DecryptedMessage> {
        return await this.transaction(
            async (ctx) => await ctx.decryptMessage(conversationId, payload)
        );
    }

    /**
     * See {@link CoreCryptoContext.encryptMessage}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.encryptMessage} instead.
     */
    async encryptMessage(
        conversationId: ConversationId,
        message: Uint8Array
    ): Promise<Uint8Array> {
        return await this.transaction(
            async (ctx) => await ctx.encryptMessage(conversationId, message)
        );
    }

    /**
     * See {@link CoreCryptoContext.processWelcomeMessage}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.processWelcomeMessage} instead.
     */
    async processWelcomeMessage(
        welcomeMessage: Uint8Array,
        configuration: CustomConfiguration = {}
    ): Promise<WelcomeBundle> {
        return await this.transaction(
            async (ctx) =>
                await ctx.processWelcomeMessage(welcomeMessage, configuration)
        );
    }

    /**
     * See {@link CoreCryptoContext.clientPublicKey}.
     *
     * @param ciphersuite - of the signature key to get
     * @param credentialType - of the public key to look for
     * @returns the client's public signature key
     */
    async clientPublicKey(
        ciphersuite: Ciphersuite,
        credentialType: CredentialType
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.client_public_key(ciphersuite, credentialType)
        );
    }

    /**
     * See {@link CoreCryptoContext.clientValidKeypackagesCount}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.clientValidKeypackagesCount} instead.
     */
    async clientValidKeypackagesCount(
        ciphersuite: Ciphersuite,
        credentialType: CredentialType
    ): Promise<number> {
        return await this.transaction(
            async (ctx) =>
                await ctx.clientValidKeypackagesCount(
                    ciphersuite,
                    credentialType
                )
        );
    }

    /**
     * See {@link CoreCryptoContext.clientKeypackages}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.clientKeypackages} instead.
     */
    async clientKeypackages(
        ciphersuite: Ciphersuite,
        credentialType: CredentialType,
        amountRequested: number
    ): Promise<Array<Uint8Array>> {
        return await this.transaction(
            async (ctx) =>
                await ctx.clientKeypackages(
                    ciphersuite,
                    credentialType,
                    amountRequested
                )
        );
    }

    /**
     * See {@link CoreCryptoContext.deleteKeypackages}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.deleteKeypackages} instead.
     */
    async deleteKeypackages(refs: Uint8Array[]): Promise<void> {
        return await this.transaction(
            async (ctx) => await ctx.deleteKeypackages(refs)
        );
    }

    /**
     * See {@link CoreCryptoContext.addClientsToConversation}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.addClientsToConversation} instead.
     */
    async addClientsToConversation(
        conversationId: ConversationId,
        keyPackages: Uint8Array[]
    ): Promise<MemberAddedMessages> {
        return await this.transaction(
            async (ctx) =>
                await ctx.addClientsToConversation(conversationId, keyPackages)
        );
    }

    /**
     * See {@link CoreCryptoContext.removeClientsFromConversation}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.removeClientsFromConversation} instead.
     */
    async removeClientsFromConversation(
        conversationId: ConversationId,
        clientIds: ClientId[]
    ): Promise<CommitBundle> {
        return await this.transaction(
            async (ctx) =>
                await ctx.removeClientsFromConversation(
                    conversationId,
                    clientIds
                )
        );
    }

    /**
     * See {@link CoreCryptoContext.updateKeyingMaterial}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.updateKeyingMaterial} instead.
     */
    async updateKeyingMaterial(
        conversationId: ConversationId
    ): Promise<CommitBundle> {
        return await this.transaction(
            async (ctx) => await ctx.updateKeyingMaterial(conversationId)
        );
    }

    /**
     * Creates an update commit which replaces your leaf containing basic credentials with a leaf node containing x509 credentials in the conversation.
     *
     * NOTE: you can only call this after you've completed the enrollment for an end-to-end identity, calling this without
     * a valid end-to-end identity will result in an error.
     *
     * **CAUTION**: {@link CoreCrypto.commitAccepted} **HAS TO** be called afterward **ONLY IF** the Delivery Service responds
     * '200 OK' to the {@link CommitBundle} upload. It will "merge" the commit locally i.e. increment the local group
     * epoch, use new encryption secrets etc...
     *
     * @param conversationId - The ID of the conversation
     *
     * @returns A {@link CommitBundle}
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiRotate} instead.
     */
    async e2eiRotate(conversationId: ConversationId): Promise<CommitBundle> {
        return await this.transaction(
            async (ctx) => await ctx.e2eiRotate(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.commitPendingProposals}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.commitPendingProposals} instead.
     */
    async commitPendingProposals(
        conversationId: ConversationId
    ): Promise<CommitBundle | undefined> {
        return await this.transaction(
            async (ctx) => await ctx.commitPendingProposals(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.newProposal}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.newProposal} instead.
     */
    async newProposal(
        proposalType: ProposalType,
        args: ProposalArgs | AddProposalArgs | RemoveProposalArgs
    ): Promise<ProposalBundle> {
        return await this.transaction(
            async (ctx) => await ctx.newProposal(proposalType, args)
        );
    }

    /**
     * See {@link CoreCryptoContext.newExternalProposal}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.newExternalProposal} instead.
     */
    async newExternalProposal(
        externalProposalType: ExternalProposalType,
        args: ExternalAddProposalArgs
    ): Promise<Uint8Array> {
        return await this.transaction(
            async (ctx) =>
                await ctx.newExternalProposal(externalProposalType, args)
        );
    }

    /**
     * See {@link CoreCryptoContext.joinByExternalCommit}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.joinByExternalCommit} instead.
     */
    async joinByExternalCommit(
        groupInfo: Uint8Array,
        credentialType: CredentialType,
        configuration: CustomConfiguration = {}
    ): Promise<ConversationInitBundle> {
        return await this.transaction(
            async (ctx) =>
                await ctx.joinByExternalCommit(
                    groupInfo,
                    credentialType,
                    configuration
                )
        );
    }

    /**
     * See {@link CoreCryptoContext.mergePendingGroupFromExternalCommit}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.mergePendingGroupFromExternalCommit} instead.
     */
    async mergePendingGroupFromExternalCommit(
        conversationId: ConversationId
    ): Promise<BufferedDecryptedMessage[] | undefined> {
        return await this.transaction(
            async (ctx) =>
                await ctx.mergePendingGroupFromExternalCommit(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.clearPendingGroupFromExternalCommit}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.clearPendingGroupFromExternalCommit} instead.
     */
    async clearPendingGroupFromExternalCommit(
        conversationId: ConversationId
    ): Promise<void> {
        return await this.transaction(
            async (ctx) =>
                await ctx.clearPendingGroupFromExternalCommit(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.commitAccepted}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.commitAccepted} instead.
     */
    async commitAccepted(
        conversationId: ConversationId
    ): Promise<BufferedDecryptedMessage[] | undefined> {
        return await this.transaction(
            async (ctx) => await ctx.commitAccepted(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.clearPendingProposal}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.clearPendingProposal} instead.
     */
    async clearPendingProposal(
        conversationId: ConversationId,
        proposalRef: ProposalRef
    ): Promise<void> {
        return await this.transaction(
            async (ctx) =>
                await ctx.clearPendingProposal(conversationId, proposalRef)
        );
    }

    /**
     * See {@link CoreCryptoContext.clearPendingCommit}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.clearPendingCommit} instead.
     */
    async clearPendingCommit(conversationId: ConversationId): Promise<void> {
        return await this.transaction(
            async (ctx) => await ctx.clearPendingCommit(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.exportSecretKey}.
     *
     * @param conversationId - The group's ID
     * @param keyLength - the length of the key to be derived. If the value is higher than the
     * bounds of `u16` or the context hash * 255, an error will be returned
     *
     * @returns A `Uint8Array` representing the derived key
     */
    async exportSecretKey(
        conversationId: ConversationId,
        keyLength: number
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.export_secret_key(conversationId, keyLength)
        );
    }

    /**
     * See {@link CoreCryptoContext.getExternalSender}.
     *
     * @param conversationId - The group's ID
     *
     * @returns A `Uint8Array` representing the external sender raw public key
     */
    async getExternalSender(
        conversationId: ConversationId
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.get_external_sender(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.getClientIds}.
     *
     * @param conversationId - The group's ID
     *
     * @returns A list of clients from the members of the group
     */
    async getClientIds(conversationId: ConversationId): Promise<ClientId[]> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.get_client_ids(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.randomBytes}.
     *
     * @param length - The number of bytes to be returned in the `Uint8Array`
     *
     * @returns A `Uint8Array` buffer that contains `length` cryptographically-secure random bytes
     */
    async randomBytes(length: number): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(this.#cc.random_bytes(length));
    }

    /**
     * Allows to reseed {@link CoreCrypto}'s internal CSPRNG with a new seed.
     *
     * @param seed - **exactly 32** bytes buffer seed
     */
    async reseedRng(seed: Uint8Array): Promise<void> {
        if (seed.length !== 32) {
            throw new Error(
                `The seed length needs to be exactly 32 bytes. ${seed.length} bytes provided.`
            );
        }

        return await CoreCryptoError.asyncMapErr(this.#cc.reseed_rng(seed));
    }

    /**
     * Initializes the proteus client
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusInit} instead.
     */
    async proteusInit(): Promise<void> {
        return await this.transaction(async (ctx) => await ctx.proteusInit());
    }

    /**
     * Create a Proteus session using a prekey
     *
     * @param sessionId - ID of the Proteus session
     * @param prekey - CBOR-encoded Proteus prekey of the other client
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusSessionFromPrekey} instead.
     */
    async proteusSessionFromPrekey(
        sessionId: string,
        prekey: Uint8Array
    ): Promise<void> {
        return await this.transaction(
            async (ctx) => await ctx.proteusSessionFromPrekey(sessionId, prekey)
        );
    }

    /**
     * Create a Proteus session from a handshake message
     *
     * @param sessionId - ID of the Proteus session
     * @param envelope - CBOR-encoded Proteus message
     *
     * @returns A `Uint8Array` containing the message that was sent along with the session handshake
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusSessionFromMessage} instead.
     */
    async proteusSessionFromMessage(
        sessionId: string,
        envelope: Uint8Array
    ): Promise<Uint8Array> {
        return await this.transaction(
            async (ctx) =>
                await ctx.proteusSessionFromMessage(sessionId, envelope)
        );
    }

    /**
     * Locally persists a session to the keystore
     *
     * **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
     *
     * @param sessionId - ID of the Proteus session
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusSessionSave} instead.
     */
    async proteusSessionSave(sessionId: string): Promise<void> {
        return await this.transaction(
            async (ctx) => await ctx.proteusSessionSave(sessionId)
        );
    }

    /**
     * Deletes a session
     * Note: this also deletes the persisted data within the keystore
     *
     * @param sessionId - ID of the Proteus session
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusSessionDelete} instead.
     */
    async proteusSessionDelete(sessionId: string): Promise<void> {
        return await this.transaction(
            async (ctx) => await ctx.proteusSessionDelete(sessionId)
        );
    }

    /**
     * Checks if a session exists
     *
     * @param sessionId - ID of the Proteus session
     *
     * @returns whether the session exists or not
     */
    async proteusSessionExists(sessionId: string): Promise<boolean> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.proteus_session_exists(sessionId)
        );
    }

    /**
     * Decrypt an incoming message for an existing Proteus session
     *
     * @param sessionId - ID of the Proteus session
     * @param ciphertext - CBOR encoded, encrypted proteus message
     * @returns The decrypted payload contained within the message
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusDecrypt} instead.
     */
    async proteusDecrypt(
        sessionId: string,
        ciphertext: Uint8Array
    ): Promise<Uint8Array> {
        return await this.transaction(
            async (ctx) => await ctx.proteusDecrypt(sessionId, ciphertext)
        );
    }

    /**
     * Encrypt a message for a given Proteus session
     *
     * @param sessionId - ID of the Proteus session
     * @param plaintext - payload to encrypt
     * @returns The CBOR-serialized encrypted message
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusEncrypt} instead.
     */
    async proteusEncrypt(
        sessionId: string,
        plaintext: Uint8Array
    ): Promise<Uint8Array> {
        return await this.transaction(
            async (ctx) => await ctx.proteusEncrypt(sessionId, plaintext)
        );
    }

    /**
     * Batch encryption for proteus messages
     * This is used to minimize FFI roundtrips when used in the context of a multi-client session (i.e. conversation)
     *
     * @param sessions - List of Proteus session IDs to encrypt the message for
     * @param plaintext - payload to encrypt
     * @returns A map indexed by each session ID and the corresponding CBOR-serialized encrypted message for this session
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusEncryptBatched} instead.
     */
    async proteusEncryptBatched(
        sessions: string[],
        plaintext: Uint8Array
    ): Promise<Map<string, Uint8Array>> {
        return await this.transaction(
            async (ctx) => await ctx.proteusEncryptBatched(sessions, plaintext)
        );
    }

    /**
     * Creates a new prekey with the requested ID.
     *
     * @param prekeyId - ID of the PreKey to generate. This cannot be bigger than a u16
     * @returns: A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusNewPrekey} instead.
     */
    async proteusNewPrekey(prekeyId: number): Promise<Uint8Array> {
        return await this.transaction(
            async (ctx) => await ctx.proteusNewPrekey(prekeyId)
        );
    }

    /**
     * Creates a new prekey with an automatically generated ID..
     *
     * @returns A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey accompanied by its ID
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusNewPrekeyAuto} instead.
     */
    async proteusNewPrekeyAuto(): Promise<ProteusAutoPrekeyBundle> {
        return await this.transaction(
            async (ctx) => await ctx.proteusNewPrekeyAuto()
        );
    }

    /**
     * Proteus last resort prekey stuff
     *
     * @returns A CBOR-serialize version of the PreKeyBundle associated with the last resort PreKey (holding the last resort prekey id)
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusLastResortPrekey} instead.
     */
    async proteusLastResortPrekey(): Promise<Uint8Array> {
        return await this.transaction(
            async (ctx) => await ctx.proteusLastResortPrekey()
        );
    }

    /**
     * @returns The last resort PreKey id
     */
    static proteusLastResortPrekeyId(): number {
        this.#assertModuleLoaded();
        return CoreCryptoFfi.proteus_last_resort_prekey_id();
    }

    /**
     * Proteus public key fingerprint
     * It's basically the public key encoded as an hex string
     *
     * @returns Hex-encoded public key string
     */
    async proteusFingerprint(): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.proteus_fingerprint()
        );
    }

    /**
     * Proteus session local fingerprint
     *
     * @param sessionId - ID of the Proteus session
     * @returns Hex-encoded public key string
     */
    async proteusFingerprintLocal(sessionId: string): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.proteus_fingerprint_local(sessionId)
        );
    }

    /**
     * Proteus session remote fingerprint
     *
     * @param sessionId - ID of the Proteus session
     * @returns Hex-encoded public key string
     */
    async proteusFingerprintRemote(sessionId: string): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.proteus_fingerprint_remote(sessionId)
        );
    }

    /**
     * Hex-encoded fingerprint of the given prekey
     *
     * @param prekey - the prekey bundle to get the fingerprint from
     * @returns Hex-encoded public key string
     **/
    static proteusFingerprintPrekeybundle(prekey: Uint8Array): string {
        try {
            return CoreCryptoFfi.proteus_fingerprint_prekeybundle(prekey);
        } catch (e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Imports all the data stored by Cryptobox into the CoreCrypto keystore
     *
     * @param storeName - The name of the IndexedDB store where the data is stored
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.proteusCryptoboxMigrate} instead.
     */
    async proteusCryptoboxMigrate(storeName: string): Promise<void> {
        return await this.transaction(
            async (ctx) => await ctx.proteusCryptoboxMigrate(storeName)
        );
    }

    /**
     * Note: this call clears out the code and resets it to 0 (aka no error)
     * @returns the last proteus error code that occured.
     */
    async proteusLastErrorCode(): Promise<number> {
        return await this.#cc.proteus_last_error_code();
    }

    /**
     * See {@link CoreCryptoContext.e2eiNewEnrollment}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiNewEnrollment} instead.
     */
    async e2eiNewEnrollment(
        clientId: string,
        displayName: string,
        handle: string,
        expirySec: number,
        ciphersuite: Ciphersuite,
        team?: string
    ): Promise<E2eiEnrollment> {
        return await this.transaction(
            async (ctx) =>
                await ctx.e2eiNewEnrollment(
                    clientId,
                    displayName,
                    handle,
                    expirySec,
                    ciphersuite,
                    team
                )
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiNewActivationEnrollment}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiNewActivationEnrollment} instead.
     */
    async e2eiNewActivationEnrollment(
        displayName: string,
        handle: string,
        expirySec: number,
        ciphersuite: Ciphersuite,
        team?: string
    ): Promise<E2eiEnrollment> {
        return await this.transaction(
            async (ctx) =>
                await ctx.e2eiNewActivationEnrollment(
                    displayName,
                    handle,
                    expirySec,
                    ciphersuite,
                    team
                )
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiNewRotateEnrollment}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiNewRotateEnrollment} instead.
     */
    async e2eiNewRotateEnrollment(
        expirySec: number,
        ciphersuite: Ciphersuite,
        displayName?: string,
        handle?: string,
        team?: string
    ): Promise<E2eiEnrollment> {
        return await this.transaction(
            async (ctx) =>
                await ctx.e2eiNewRotateEnrollment(
                    expirySec,
                    ciphersuite,
                    displayName,
                    handle,
                    team
                )
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiMlsInitOnly}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiMlsInitOnly} instead.
     */
    async e2eiMlsInitOnly(
        enrollment: E2eiEnrollment,
        certificateChain: string,
        nbKeyPackage?: number
    ): Promise<string[] | undefined> {
        return await this.transaction(
            async (ctx) =>
                await ctx.e2eiMlsInitOnly(
                    enrollment,
                    certificateChain,
                    nbKeyPackage
                )
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiDumpPKIEnv}.
     *
     * @returns a struct with different fields representing the PKI environment as PEM strings
     */
    async e2eiDumpPKIEnv(): Promise<E2eiDumpedPkiEnv | undefined> {
        return await this.#cc.e2ei_dump_pki_env();
    }

    /**
     * See {@link CoreCryptoContext.e2eiIsPKIEnvSetup}.
     * @returns whether the E2EI PKI environment is setup (i.e. Root CA, Intermediates, CRLs)
     */
    async e2eiIsPKIEnvSetup(): Promise<boolean> {
        return await this.#cc.e2ei_is_pki_env_setup();
    }

    /**
     * See {@link CoreCryptoContext.e2eiRegisterAcmeCA}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiRegisterAcmeCA} instead.
     */
    async e2eiRegisterAcmeCA(trustAnchorPEM: string): Promise<void> {
        return await this.transaction(
            async (ctx) => await ctx.e2eiRegisterAcmeCA(trustAnchorPEM)
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiRegisterIntermediateCA}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiRegisterIntermediateCA} instead.
     */
    async e2eiRegisterIntermediateCA(
        certPEM: string
    ): Promise<string[] | undefined> {
        return await this.transaction(
            async (ctx) => await ctx.e2eiRegisterIntermediateCA(certPEM)
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiRegisterCRL}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiRegisterCRL} instead.
     */
    async e2eiRegisterCRL(
        crlDP: string,
        crlDER: Uint8Array
    ): Promise<CRLRegistration> {
        return await this.transaction(
            async (ctx) => await ctx.e2eiRegisterCRL(crlDP, crlDER)
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiRotateAll}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiRotateAll} instead.
     */
    async e2eiRotateAll(
        enrollment: E2eiEnrollment,
        certificateChain: string,
        newKeyPackageCount: number
    ): Promise<RotateBundle> {
        return await this.transaction(
            async (ctx) =>
                await ctx.e2eiRotateAll(
                    enrollment,
                    certificateChain,
                    newKeyPackageCount
                )
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiEnrollmentStash}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiEnrollmentStash} instead.
     */
    async e2eiEnrollmentStash(enrollment: E2eiEnrollment): Promise<Uint8Array> {
        return await this.transaction(
            async (ctx) => await ctx.e2eiEnrollmentStash(enrollment)
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiEnrollmentStashPop}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiEnrollmentStashPop} instead.
     */
    async e2eiEnrollmentStashPop(handle: Uint8Array): Promise<E2eiEnrollment> {
        return await this.transaction(
            async (ctx) => await ctx.e2eiEnrollmentStashPop(handle)
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiConversationState}.
     *
     * @deprecated Create a transaction with {@link CoreCrypto.transaction}
     * and use {@link CoreCryptoContext.e2eiConversationState} instead.
     */
    async e2eiConversationState(
        conversationId: ConversationId
    ): Promise<E2eiConversationState> {
        return await this.transaction(
            async (ctx) => await ctx.e2eiConversationState(conversationId)
        );
    }

    /**
     * See {@link CoreCryptoContext.e2eiIsEnabled}.
     *
     * @param ciphersuite of the credential to check
     * @returns true if end-to-end identity is enabled for the given ciphersuite
     */
    async e2eiIsEnabled(ciphersuite: Ciphersuite): Promise<boolean> {
        return await CoreCryptoError.asyncMapErr(
            this.#cc.e2ei_is_enabled(ciphersuite)
        );
    }

    /**
     * See {@link CoreCryptoContext.getDeviceIdentities}.
     *
     * @param conversationId - identifier of the conversation
     * @param deviceIds - identifiers of the devices
     * @returns identities or if no member has a x509 certificate, it will return an empty List
     */
    async getDeviceIdentities(
        conversationId: ConversationId,
        deviceIds: ClientId[]
    ): Promise<WireIdentity[]> {
        return (
            await CoreCryptoError.asyncMapErr(
                this.#cc.get_device_identities(conversationId, deviceIds)
            )
        ).map(mapWireIdentity);
    }

    /**
     * See {@link CoreCryptoContext.getUserIdentities}.
     *
     * @param conversationId - identifier of the conversation
     * @param userIds - user identifiers hyphenated UUIDv4 e.g. 'bd4c7053-1c5a-4020-9559-cd7bf7961954'
     * @returns a Map with all the identities for a given users. Consumers are then recommended to reduce those identities to determine the actual status of a user.
     */
    async getUserIdentities(
        conversationId: ConversationId,
        userIds: string[]
    ): Promise<Map<string, WireIdentity[]>> {
        const map: Map<string, CoreCryptoFfiTypes.WireIdentity[]> =
            await CoreCryptoError.asyncMapErr(
                this.#cc.get_user_identities(conversationId, userIds)
            );

        const mapFixed: Map<string, WireIdentity[]> = new Map();

        for (const [userId, identities] of map) {
            const mappedIdentities = identities.flatMap((identity) => {
                const mappedIdentity = mapWireIdentity(identity);
                return mappedIdentity ? [mappedIdentity] : [];
            });
            mapFixed.set(userId, mappedIdentities);
        }

        return mapFixed;
    }

    /**
     * See {@link CoreCryptoContext.getCredentialInUse}.
     *
     * @param groupInfo - a TLS encoded GroupInfo fetched from the Delivery Service
     * @param credentialType - kind of Credential to check usage of. Defaults to X509 for now as no other value will give any result.
     * @returns see {@link E2eiConversationState}
     */
    async getCredentialInUse(
        groupInfo: Uint8Array,
        credentialType: CredentialType = CredentialType.X509
    ): Promise<E2eiConversationState> {
        const state = await CoreCryptoError.asyncMapErr(
            this.#cc.get_credential_in_use(groupInfo, credentialType)
        );
        return normalizeEnum(E2eiConversationState, state);
    }

    /**
     * Returns the current version of {@link CoreCrypto}
     *
     * @returns The `core-crypto-ffi` version as defined in its `Cargo.toml` file
     */
    static version(): string {
        this.#assertModuleLoaded();
        return CoreCryptoFfi.version();
    }

    /**
     * Returns build metadata for the {@link CoreCrypto} libary.
     *
     * @returns varous build metadata for `core-crypto`.
     */
    static buildMetadata(): CoreCryptoFfiTypes.BuildMetadata {
        this.#assertModuleLoaded();
        return CoreCryptoFfi.build_metadata();
    }
}

type JsonRawData = Uint8Array;

export class E2eiEnrollment {
    /** @hidden */
    #enrollment: CoreCryptoFfiTypes.FfiWireE2EIdentity;

    /** @hidden */
    constructor(e2ei: unknown) {
        this.#enrollment = e2ei as CoreCryptoFfiTypes.FfiWireE2EIdentity;
    }

    free() {
        this.#enrollment.free();
    }

    /**
     * Should only be used internally
     */
    inner(): unknown {
        return this.#enrollment as CoreCryptoFfiTypes.FfiWireE2EIdentity;
    }

    /**
     * Parses the response from `GET /acme/{provisioner-name}/directory`.
     * Use this {@link AcmeDirectory} in the next step to fetch the first nonce from the acme server. Use
     * {@link AcmeDirectory.newNonce}.
     *
     * @param directory HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
     */
    async directoryResponse(directory: JsonRawData): Promise<AcmeDirectory> {
        const ffiRet: CoreCryptoFfiTypes.AcmeDirectory =
            await CoreCryptoError.asyncMapErr(
                this.#enrollment.directory_response(directory)
            );

        return {
            newNonce: ffiRet.new_nonce,
            newAccount: ffiRet.new_account,
            newOrder: ffiRet.new_order,
            revokeCert: ffiRet.revoke_cert,
        };
    }

    /**
     * For creating a new acme account. This returns a signed JWS-alike request body to send to
     * `POST /acme/{provisioner-name}/new-account`.
     *
     * @param previousNonce you got from calling `HEAD {@link AcmeDirectory.newNonce}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
     */
    async newAccountRequest(previousNonce: string): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_account_request(previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/new-account`.
     * @param account HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
     */
    async newAccountResponse(account: JsonRawData): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_account_response(account)
        );
    }

    /**
     * Creates a new acme order for the handle (userId + display name) and the clientId.
     *
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/new-account`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async newOrderRequest(previousNonce: string): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_order_request(previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/new-order`.
     *
     * @param order HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async newOrderResponse(order: JsonRawData): Promise<NewAcmeOrder> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_order_response(order)
        );
    }

    /**
     * Creates a new authorization request.
     *
     * @param url one of the URL in new order's authorizations (use {@link NewAcmeOrder.authorizations} from {@link newOrderResponse})
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/new-order` (or from the
     * previous to this method if you are creating the second authorization)
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
     */
    async newAuthzRequest(
        url: string,
        previousNonce: string
    ): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_authz_request(url, previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/authz/{authz-id}`
     *
     * @param authz HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
     */
    async newAuthzResponse(authz: JsonRawData): Promise<NewAcmeAuthz> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_authz_response(authz)
        );
    }

    /**
     * Generates a new client Dpop JWT token. It demonstrates proof of possession of the nonces
     * (from wire-server & acme server) and will be verified by the acme server when verifying the
     * challenge (in order to deliver a certificate).
     *
     * Then send it to `POST /clients/{id}/access-token`
     * {@link https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token} on wire-server.
     *
     * @param expirySecs of the client Dpop JWT. This should be equal to the grace period set in Team Management
     * @param backendNonce you get by calling `GET /clients/token/nonce` on wire-server as defined here {@link https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/get_clients__client__nonce}
     */
    async createDpopToken(
        expirySecs: number,
        backendNonce: string
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.create_dpop_token(expirySecs, backendNonce)
        );
    }

    /**
     * Creates a new challenge request for Wire Dpop challenge.
     *
     * @param accessToken returned by wire-server from https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    async newDpopChallengeRequest(
        accessToken: string,
        previousNonce: string
    ): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_dpop_challenge_request(
                accessToken,
                previousNonce
            )
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for the DPoP challenge.
     *
     * @param challenge HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    async newDpopChallengeResponse(challenge: JsonRawData): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_dpop_challenge_response(challenge)
        );
    }

    /**
     * Creates a new challenge request for Wire Oidc challenge.
     *
     * @param idToken you get back from Identity Provider
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    async newOidcChallengeRequest(
        idToken: string,
        previousNonce: string
    ): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_oidc_challenge_request(idToken, previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for the OIDC challenge.
     *
     * @param cc the CoreCrypto instance
     * @param challenge HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    async newOidcChallengeResponse(challenge: JsonRawData): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_oidc_challenge_response(challenge)
        );
    }

    /**
     * Verifies that the previous challenge has been completed.
     *
     * @param orderUrl `location` header from http response you got from {@link newOrderResponse}
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/challenge/{challenge-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async checkOrderRequest(
        orderUrl: string,
        previousNonce: string
    ): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.check_order_request(orderUrl, previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/order/{order-id}`.
     *
     * @param order HTTP response body
     * @return finalize url to use with {@link finalizeRequest}
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async checkOrderResponse(order: JsonRawData): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.check_order_response(order)
        );
    }

    /**
     * Final step before fetching the certificate.
     *
     * @param previousNonce - `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async finalizeRequest(previousNonce: string): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.finalize_request(previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/order/{order-id}/finalize`.
     *
     * @param finalize HTTP response body
     * @return the certificate url to use with {@link certificateRequest}
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async finalizeResponse(finalize: JsonRawData): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.finalize_response(finalize)
        );
    }

    /**
     * Creates a request for finally fetching the x509 certificate.
     *
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}/finalize`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2
     */
    async certificateRequest(previousNonce: string): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.certificate_request(previousNonce)
        );
    }
}

/**
 * Indicates the state of a Conversation regarding end-to-end identity.
 * Note: this does not check pending state (pending commit, pending proposals) so it does not
 * consider members about to be added/removed
 */
export enum E2eiConversationState {
    /**
     * All clients have a valid E2EI certificate
     */
    Verified = 0x0001,
    /**
     * Some clients are either still Basic or their certificate is expired
     */
    NotVerified = 0x0002,
    /**
     * All clients are still Basic. If all client have expired certificates, NotVerified is returned.
     */
    NotEnabled = 0x0003,
}
