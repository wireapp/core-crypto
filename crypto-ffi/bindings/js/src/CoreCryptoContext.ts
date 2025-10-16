import {
    Ciphersuite,
    ClientId,
    CoreCryptoContext as CoreCryptoContextFfi,
    CustomConfiguration,
    WireIdentity,
    ConversationId,
    KeyPackage,
    Welcome,
    type SecretKeyInterface,
    type ExternalSenderKeyInterface,
    type ClientIdInterface,
    ProteusAutoPrekeyBundle,
    DecryptedMessage,
} from "./index.web";
import * as CoreCryptoFfiTypes from "./index.web";

import { CoreCryptoError } from "./CoreCryptoError";
import {
    CredentialType,
    WelcomeBundle,
} from "./CoreCryptoMLS";

import {
    type CRLRegistration,
    crlRegistrationFromFfi,
    E2eiConversationState,
    E2eiEnrollment,
    type NewCrlDistributionPoints,
    normalizeEnum,
} from "./CoreCryptoE2EI";

import { safeBigintToNumber } from "./Conversions";
import {
    type ConversationConfiguration,
    conversationConfigurationToFfi,
} from "./ConversationConfiguration";

export class CoreCryptoContext {
    /** @hidden */
    #ctx: CoreCryptoContextFfi;

    /** @hidden */
    private constructor(ctx: CoreCryptoContextFfi) {
        this.#ctx = ctx;
    }

    /** @hidden */
    static fromFfiContext(
        ctx: CoreCryptoContextFfi
    ): CoreCryptoContext {
        return new CoreCryptoContext(ctx);
    }

    /**
     * Set arbitrary data to be retrieved by {@link getData}.
     * This is meant to be used as a check point at the end of a transaction.
     * The data should be limited to a reasonable size.
     */
    async setData(data: ArrayBuffer): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#ctx.setData(data));
    }

    /**
     * Get data if it has previously been set by {@link setData}, or `undefined` otherwise.
     * This is meant to be used as a check point at the end of a transaction.
     */
    async getData(): Promise<ArrayBuffer | undefined> {
        return await CoreCryptoError.asyncMapErr(this.#ctx.getData());
    }

    /**
     * Use this after {@link CoreCrypto.init} when you have a clientId. It initializes MLS.
     *
     * @param clientId - required
     * @param ciphersuites - All the ciphersuites supported by this MLS client
     */
    async mlsInit(
        clientId: ClientId,
        ciphersuites: Ciphersuite[]
    ): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.mlsInit(clientId, ciphersuites)
        );
    }

    /**
     * Checks if the Client is member of a given conversation and if the MLS Group is loaded up
     *
     * @returns Whether the given conversation ID exists
     *
     * @example
     * ```ts
     *  const cc = await CoreCrypto.init({ databaseName: "test", key: "test", clientId: "test" });
     *  const encoder = new TextEncoder();
     *  if (await cc.conversationExists(encoder.encode("my super chat"))) {
     *    // Do something
     *  } else {
     *    // Do something else
     *  }
     * ```
     */
    async conversationExists(conversationId: ConversationId): Promise<boolean> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.conversationExists(conversationId)
        );
    }

    /**
     * Marks a conversation as child of another one
     * This will mostly affect the behavior of the callbacks (the parentConversationClients parameter will be filled)
     *
     * @param childId - conversation identifier of the child conversation
     * @param parentId - conversation identifier of the parent conversation
     */
    async markConversationAsChildOf(
        childId: ConversationId,
        parentId: ConversationId
    ): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.markConversationAsChildOf(childId, parentId)
        );
    }

    /**
     * Returns the current epoch of a conversation
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
        const epoch = await CoreCryptoError.asyncMapErr(
            this.#ctx.conversationEpoch(conversationId)
        );
        return safeBigintToNumber(epoch);
    }

    /**
     * Returns the ciphersuite of a conversation
     *
     * @returns the ciphersuite of the conversation
     */
    async conversationCiphersuite(
        conversationId: ConversationId
    ): Promise<Ciphersuite> {
        const cs = await CoreCryptoError.asyncMapErr(
            this.#ctx.conversationCiphersuite(conversationId)
        );
        return cs;
    }

    /**
     * Wipes and destroys the local storage of a given conversation / MLS group
     *
     * @param conversationId - The ID of the conversation to remove
     */
    async wipeConversation(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.wipeConversation(conversationId)
        );
    }

    /**
     * Creates a new conversation with the current client being the sole member
     * You will want to use {@link addClientsToConversation} afterwards to add clients to this conversation
     *
     * @param conversationId - The conversation ID; You can either make them random or let the backend attribute MLS group IDs
     * @param creatorCredentialType - kind of credential the creator wants to create the group with
     * @param configuration - configuration of the MLS group
     * @param configuration.ciphersuite - The {@link Ciphersuite} that is chosen to be the group's
     * @param configuration.externalSenders - Array of Client IDs that are qualified as external senders within the group
     */
    async createConversation(
        conversationId: ConversationId,
        creatorCredentialType: CredentialType,
        configuration: ConversationConfiguration = {}
    ) {
        const config = conversationConfigurationToFfi(configuration);
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.createConversation(
                conversationId,
                creatorCredentialType,
                config
            )
        );
    }

    /**
     * Decrypts a message for a given conversation.
     *
     * Note: you should catch & ignore the following error reasons:
     * * "We already decrypted this message once"
     * * "You tried to join with an external commit but did not merge it yet. We will reapply this message for you when you merge your external commit"
     * * "Incoming message is for a future epoch. We will buffer it until the commit for that epoch arrives"
     *
     * @param conversationId - The ID of the conversation
     * @param payload - The encrypted message buffer
     *
     * @returns a {@link DecryptedMessage}. Note that {@link DecryptedMessage#message} is `undefined` when the encrypted payload contains a system message such a proposal or commit
     */
    async decryptMessage(
        conversationId: ConversationId,
        payload: ArrayBuffer
    ): Promise<DecryptedMessage> {
        if (!payload?.byteLength) {
            throw new Error("decryptMessage payload is empty or null");
        }

        return await CoreCryptoError.asyncMapErr(
            this.#ctx.decryptMessage(conversationId, payload)
        );

    }

    /**
     * Encrypts a message for a given conversation
     *
     * @param conversationId - The ID of the conversation
     * @param message - The plaintext message to encrypt
     *
     * @returns The encrypted payload for the given group. This needs to be fanned out to the other members of the group.
     */
    async encryptMessage(
        conversationId: ConversationId,
        message: ArrayBuffer
    ): Promise<ArrayBuffer> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.encryptMessage(conversationId, message)
        );
    }

    /**
     * Ingest a TLS-serialized MLS welcome message to join an existing MLS group
     *
     * You have to catch the error with this reason "Although this Welcome seems valid, the local KeyPackage
     * it references has already been deleted locally. Join this group with an external commit", ignore it and then
     * join this group via {@link CoreCryptoContext.joinByExternalCommit}.
     *
     * @param welcomeMessage - TLS-serialized MLS Welcome message
     * @param configuration - configuration of the MLS group
     * @returns The conversation ID of the newly joined group. You can use the same ID to decrypt/encrypt messages
     */
    async processWelcomeMessage(
        welcomeMessage: Welcome,
        configuration: Partial<CustomConfiguration> = {}
    ): Promise<WelcomeBundle> {
        const { keyRotationSpan, wirePolicy } = configuration || {};
        const config = CustomConfiguration.create({ keyRotationSpan, wirePolicy });
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.processWelcomeMessage(welcomeMessage, config)
        );
    }

    /**
     * Get the client's public signature key. To upload to the DS for further backend side validation
     *
     * @param ciphersuite - of the signature key to get
     * @param credentialType - of the public key to look for
     * @returns the client's public signature key
     */
    async clientPublicKey(
        ciphersuite: Ciphersuite,
        credentialType: CredentialType
    ): Promise<ArrayBuffer> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.clientPublicKey(ciphersuite, credentialType)
        );
    }

    /**
     *
     * @param ciphersuite - of the KeyPackages to count
     * @param credentialType - of the KeyPackages to count
     * @returns The amount of valid, non-expired KeyPackages that are persisted in the backing storage
     */
    async clientValidKeypackagesCount(
        ciphersuite: Ciphersuite,
        credentialType: CredentialType
    ): Promise<number> {
        const kpCount = await CoreCryptoError.asyncMapErr(
            this.#ctx.clientValidKeypackagesCount(
                ciphersuite,
                credentialType
            )
        );
        return safeBigintToNumber(kpCount);
    }

    /**
     * Fetches a requested amount of keypackages
     *
     * @param ciphersuite - of the KeyPackages to generate
     * @param credentialType - of the KeyPackages to generate
     * @param amountRequested - The amount of keypackages requested
     * @returns An array of length `amountRequested` containing TLS-serialized KeyPackages
     */
    async clientKeypackages(
        ciphersuite: Ciphersuite,
        credentialType: CredentialType,
        amountRequested: number
    ): Promise<Array<ArrayBuffer>> {
        const kps = await CoreCryptoError.asyncMapErr(
            this.#ctx.clientKeypackages(
                ciphersuite,
                credentialType,
                amountRequested
            )
        );
        return kps.map((kp) => kp.copyBytes());
    }

    /**
     * Adds new clients to a conversation, assuming the current client has the right to add new clients to the conversation.
     *
     * Sends the corresponding commit via {@link MlsTransport.sendCommitBundle} and merges it if the call is successful.
     *
     * @param conversationId - The ID of the conversation
     * @param keyPackages - KeyPackages of the new clients to add
     *
     * @returns Potentially a list of newly discovered crl distribution points
     */
    async addClientsToConversation(
        conversationId: ConversationId,
        keyPackages: ArrayBuffer[]
    ): Promise<NewCrlDistributionPoints> {
        const kps = keyPackages.map((bytes) => new KeyPackage(bytes));
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.addClientsToConversation(conversationId, kps)
        );
    }

    /**
     * Removes the provided clients from a conversation; Assuming those clients exist and the current client is allowed
     * to do so, otherwise this operation does nothing.
     *
     * @param conversationId - The ID of the conversation
     * @param clientIds - Array of Client IDs to remove.
     */
    async removeClientsFromConversation(
        conversationId: ConversationId,
        clientIds: ClientId[]
    ): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.removeClientsFromConversation(
                conversationId,
                clientIds
            )
        );
    }

    /**
     * Update the keying material of the conversation.
     *
     * @param conversationId - The ID of the conversation
     */
    async updateKeyingMaterial(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.updateKeyingMaterial(conversationId)
        );
    }

    /**
     * Commits the local pending proposals.
     *
     * Sends the corresponding commit via {@link MlsTransport.sendCommitBundle}
     * and merges it if the call is successful.
     *
     * @param conversationId - The ID of the conversation
     */
    async commitPendingProposals(
        conversationId: ConversationId
    ): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.commitPendingProposals(conversationId)
        );
    }

    /**
     * "Apply" to join a group through its GroupInfo.
     *
     * Sends the corresponding commit via {@link MlsTransport.sendCommitBundle}
     * and creates the group if the call is successful.
     *
     * @param groupInfo - a TLS encoded GroupInfo fetched from the Delivery Service
     * @param credentialType - kind of Credential to use for joining this group. If {@link CredentialType.Basic} is
     * chosen and no Credential has been created yet for it, a new one will be generated.
     * @param configuration - configuration of the MLS group
     * When {@link CredentialType.X509} is chosen, it fails when no Credential has been created for the given {@link Ciphersuite}.
     *
     * @return see {@link WelcomeBundle}
     */
    async joinByExternalCommit(
        groupInfo: CoreCryptoFfiTypes.GroupInfo,
        credentialType: CredentialType,
        configuration: Partial<CustomConfiguration> = {}
    ): Promise<WelcomeBundle> {
        const { keyRotationSpan, wirePolicy } = configuration || {};
        const config = CustomConfiguration.create({ keyRotationSpan, wirePolicy });
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.joinByExternalCommit(groupInfo, config, credentialType)
        );
    }

    /**
     * Enable history sharing by generating a history client and adding it to the conversation.
     */
    async enableHistorySharing(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.enableHistorySharing(conversationId)
        );
    }

    /**
     * Disable history sharing by removing histroy clients from the conversation.
     */
    async disableHistorySharing(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.disableHistorySharing(conversationId)
        );
    }

    /**
     * Derives a new key from the group
     *
     * @param conversationId - The group's ID
     * @param keyLength - the length of the key to be derived. If the value is higher than the
     * bounds of `u16` or the context hash * 255, an error will be returned
     *
     * @returns A `ArrayBuffer` representing the derived key
     */
    async exportSecretKey(
        conversationId: ConversationId,
        keyLength: number
    ): Promise<SecretKeyInterface> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.exportSecretKey(conversationId, keyLength)
        );
    }

    /**
     * Returns the raw public key of the single external sender present in this group.
     * This should be used to initialize a subconversation
     *
     * @param conversationId - The group's ID
     *
     * @returns A `ArrayBuffer` representing the external sender raw public key
     */
    async getExternalSender(
        conversationId: ConversationId
    ): Promise<ExternalSenderKeyInterface> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.getExternalSender(conversationId)
        );
    }

    /**
     * Returns all clients from group's members
     *
     * @param conversationId - The group's ID
     *
     * @returns A list of clients from the members of the group
     */
    async getClientIds(conversationId: ConversationId): Promise<ClientIdInterface[]> {
        const ids = await CoreCryptoError.asyncMapErr(
            this.#ctx.getClientIds(conversationId)
        );
        return ids;
    }

    /**
     * Allows {@link CoreCryptoContext} to act as a CSPRNG provider
     *
     * The underlying CSPRNG algorithm is ChaCha20 and takes in account the external seed provider.
     *
     * @param length - The number of bytes to be returned in the `ArrayBuffer`
     *
     * @returns A `ArrayBuffer` buffer that contains `length` cryptographically-secure random bytes
     */
    async randomBytes(length: number): Promise<ArrayBuffer> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.randomBytes(length)
        );
    }

    /**
     * Initializes the proteus client
     */
    async proteusInit(): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#ctx.proteusInit());
    }

    /**
     * Create a Proteus session using a prekey
     *
     * @param sessionId - ID of the Proteus session
     * @param prekey - CBOR-encoded Proteus prekey of the other client
     */
    async proteusSessionFromPrekey(
        sessionId: string,
        prekey: ArrayBuffer
    ): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusSessionFromPrekey(sessionId, prekey)
        );
    }

    /**
     * Create a Proteus session from a handshake message
     *
     * @param sessionId - ID of the Proteus session
     * @param envelope - CBOR-encoded Proteus message
     *
     * @returns A `ArrayBuffer` containing the message that was sent along with the session handshake
     */
    async proteusSessionFromMessage(
        sessionId: string,
        envelope: ArrayBuffer
    ): Promise<ArrayBuffer> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusSessionFromMessage(sessionId, envelope)
        );
    }

    /**
     * Locally persists a session to the keystore
     *
     * **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
     *
     * @param sessionId - ID of the Proteus session
     */
    async proteusSessionSave(sessionId: string): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusSessionSave(sessionId)
        );
    }

    /**
     * Deletes a session
     * Note: this also deletes the persisted data within the keystore
     *
     * @param sessionId - ID of the Proteus session
     */
    async proteusSessionDelete(sessionId: string): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusSessionDelete(sessionId)
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
            this.#ctx.proteusSessionExists(sessionId)
        );
    }

    /**
     * Decrypt an incoming message for an existing Proteus session
     *
     * @param sessionId - ID of the Proteus session
     * @param ciphertext - CBOR encoded, encrypted proteus message
     * @returns The decrypted payload contained within the message
     */
    async proteusDecrypt(
        sessionId: string,
        ciphertext: ArrayBuffer
    ): Promise<ArrayBuffer> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusDecrypt(sessionId, ciphertext)
        );
    }

    /**
     * Encrypt a message for a given Proteus session
     *
     * @param sessionId - ID of the Proteus session
     * @param plaintext - payload to encrypt
     * @returns The CBOR-serialized encrypted message
     */
    async proteusEncrypt(
        sessionId: string,
        plaintext: ArrayBuffer
    ): Promise<ArrayBuffer> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusEncrypt(sessionId, plaintext)
        );
    }

    /**
     * Batch encryption for proteus messages
     * This is used to minimize FFI roundtrips when used in the context of a multi-client session (i.e. conversation)
     *
     * @param sessions - List of Proteus session IDs to encrypt the message for
     * @param plaintext - payload to encrypt
     * @returns A map indexed by each session ID and the corresponding CBOR-serialized encrypted message for this session
     */
    async proteusEncryptBatched(
        sessions: string[],
        plaintext: ArrayBuffer
    ): Promise<Map<string, ArrayBuffer>> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusEncryptBatched(sessions, plaintext)
        );
    }

    /**
     * Creates a new prekey with the requested ID.
     *
     * @param prekeyId - ID of the PreKey to generate. This cannot be bigger than a u16
     * @returns: A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey
     */
    async proteusNewPrekey(prekeyId: number): Promise<ArrayBuffer> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusNewPrekey(prekeyId)
        );
    }

    /**
     * Creates a new prekey with an automatically generated ID..
     *
     * @returns A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey accompanied by its ID
     */
    async proteusNewPrekeyAuto(): Promise<ProteusAutoPrekeyBundle> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusNewPrekeyAuto()
        );
    }

    /**
     * Proteus last resort prekey stuff
     *
     * @returns A CBOR-serialize version of the PreKeyBundle associated with the last resort PreKey (holding the last resort prekey id)
     */
    async proteusLastResortPrekey(): Promise<ArrayBuffer> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusLastResortPrekey()
        );
    }

    /**
     * @returns The last resort PreKey id
     */
    proteusLastResortPrekeyId(): number {
        return this.#ctx.proteusLastResortPrekeyId();
    }

    /**
     * Proteus public key fingerprint
     * It's basically the public key encoded as an hex string
     *
     * @returns Hex-encoded public key string
     */
    async proteusFingerprint(): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteusFingerprint()
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
            this.#ctx.proteusFingerprintLocal(sessionId)
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
            this.#ctx.proteusFingerprintRemote(sessionId)
        );
    }


    /**
     * Creates an enrollment instance with private key material you can use in order to fetch
     * a new x509 certificate from the acme server.
     *
     * @param clientId - client identifier e.g. `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
     * @param displayName - human-readable name displayed in the application e.g. `Smith, Alice M (QA)`
     * @param handle - user handle e.g. `alice.smith.qa@example.com`
     * @param expirySec - generated x509 certificate expiry
     * @param ciphersuite - for generating signing key material
     * @param team - name of the Wire team a user belongs to
     * @returns The new {@link E2eiEnrollment} enrollment instance to use with {@link CoreCryptoContext.e2eiMlsInitOnly}
     */
    async e2eiNewEnrollment(
        clientId: string,
        displayName: string,
        handle: string,
        expirySec: number,
        ciphersuite: Ciphersuite,
        team?: string
    ): Promise<E2eiEnrollment> {
        const e2ei = await CoreCryptoError.asyncMapErr(
            this.#ctx.e2eiNewEnrollment(
                clientId,
                displayName,
                handle,
                team,
                expirySec,
                ciphersuite
            )
        );
        return new E2eiEnrollment(e2ei);
    }

    /**
     * Generates an E2EI enrollment instance for a "regular" client (with a Basic credential) willing to migrate to E2EI.
     * Once the enrollment is finished, use {@link CoreCryptoContext.e2eiRotate} to do key rotation.
     *
     * @param displayName - human-readable name displayed in the application e.g. `Smith, Alice M (QA)`
     * @param handle - user handle e.g. `alice.smith.qa@example.com`
     * @param expirySec - generated x509 certificate expiry
     * @param ciphersuite - for generating signing key material
     * @param team - name of the Wire team a user belongs to
     * @returns The new {@link E2eiEnrollment} enrollment instance to use with {@link CoreCryptoContext.e2eiRotate}
     */
    async e2eiNewActivationEnrollment(
        displayName: string,
        handle: string,
        expirySec: number,
        ciphersuite: Ciphersuite,
        team?: string
    ): Promise<E2eiEnrollment> {
        const e2ei = await CoreCryptoError.asyncMapErr(
            this.#ctx.e2eiNewActivationEnrollment(
                displayName,
                handle,
                team,
                expirySec,
                ciphersuite
            )
        );
        return new E2eiEnrollment(e2ei);
    }

    /**
     * Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential)
     * having to change/rotate their credential, either because the former one is expired or it
     * has been revoked. It lets you change the DisplayName or the handle
     * if you need to. Once the enrollment is finished, use {@link CoreCryptoContext.e2eiRotate}
     * to do key rotation.
     *
     * @param expirySec - generated x509 certificate expiry
     * @param ciphersuite - for generating signing key material
     * @param displayName - human-readable name displayed in the application e.g. `Smith, Alice M (QA)`
     * @param handle - user handle e.g. `alice.smith.qa@example.com`
     * @param team - name of the Wire team a user belongs to
     * @returns The new {@link E2eiEnrollment} enrollment instance to use with {@link CoreCryptoContext.e2eiRotate}
     */
    async e2eiNewRotateEnrollment(
        expirySec: number,
        ciphersuite: Ciphersuite,
        displayName?: string,
        handle?: string,
        team?: string
    ): Promise<E2eiEnrollment> {
        const e2ei = await CoreCryptoError.asyncMapErr(
            this.#ctx.e2eiNewRotateEnrollment(
                displayName,
                handle,
                team,
                expirySec,
                ciphersuite
            )
        );
        return new E2eiEnrollment(e2ei);
    }

    /**
     * Use this method to initialize end-to-end identity when a client signs up and the grace period is already expired ;
     * that means he cannot initialize with a Basic credential
     *
     * @param enrollment - the enrollment instance used to fetch the certificates
     * @param certificateChain - the raw response from ACME server
     * @returns a MlsClient initialized with only a x509 credential
     */
    async e2eiMlsInitOnly(
        enrollment: E2eiEnrollment,
        certificateChain: string
    ): Promise<NewCrlDistributionPoints> {
        return await this.#ctx.e2eiMlsInitOnly(
            enrollment.inner(),
            certificateChain
        );
    }

    /**
     * @returns whether the E2EI PKI environment is setup (i.e. Root CA, Intermediates, CRLs)
     */
    async e2eiIsPKIEnvSetup(): Promise<boolean> {
        return await this.#ctx.e2eiIsPkiEnvSetup();
    }

    /**
     * Registers a Root Trust Anchor CA for the use in E2EI processing.
     *
     * Please note that without a Root Trust Anchor, all validations *will* fail;
     * So this is the first step to perform after initializing your E2EI client
     *
     * @param trustAnchorPEM - PEM certificate to anchor as a Trust Root
     */
    async e2eiRegisterAcmeCA(trustAnchorPEM: string): Promise<void> {
        return await this.#ctx.e2eiRegisterAcmeCa(trustAnchorPEM);
    }

    /**
     * Registers an Intermediate CA for the use in E2EI processing.
     *
     * Please note that a Root Trust Anchor CA is needed to validate Intermediate CAs;
     * You **need** to have a Root CA registered before calling this
     *
     * @param certPEM - PEM certificate to register as an Intermediate CA
     */
    async e2eiRegisterIntermediateCA(
        certPEM: string
    ): Promise<NewCrlDistributionPoints> {
        return await this.#ctx.e2eiRegisterIntermediateCa(certPEM);
    }

    /**
     * Registers a CRL for the use in E2EI processing.
     *
     * Please note that a Root Trust Anchor CA is needed to validate CRLs;
     * You **need** to have a Root CA registered before calling this
     *
     * @param crlDP - CRL Distribution Point; Basically the URL you fetched it from
     * @param crlDER - DER representation of the CRL
     *
     * @returns a {@link CRLRegistration} with the dirty state of the new CRL (see struct) and its expiration timestamp
     */
    async e2eiRegisterCRL(
        crlDP: string,
        crlDER: ArrayBuffer
    ): Promise<CRLRegistration> {
        const reg = await this.#ctx.e2eiRegisterCrl(crlDP, crlDER);
        return crlRegistrationFromFfi(reg);
    }

    /**
     * Creates an update commit which replaces your leaf containing basic credentials with a leaf node containing x509 credentials in the conversation.
     *
     * NOTE: you can only call this after you've completed the enrollment for an end-to-end identity, and saved the
     * resulting credential with {@link CoreCryptoContext.saveX509Credential}.
     * Calling this without a valid end-to-end identity will result in an error.
     *
     * Sends the corresponding commit via {@link MlsTransport.sendCommitBundle} and merges it if the call is successful.
     *
     * @param conversationId - The ID of the conversation
     */
    async e2eiRotate(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.e2eiRotate(conversationId)
        );
    }

    /**
     * Saves a new X509 credential. Requires first
     * having enrolled a new X509 certificate with either {@link CoreCryptoContext.e2eiNewActivationEnrollment}
     * or {@link CoreCryptoContext.e2eiNewRotateEnrollment}
     *
     * # Expected actions to perform after this function (in this order)
     * 1. Rotate credentials for each conversation using {@link CoreCryptoContext.e2eiRotate}
     * 2. Generate new key packages with {@link CoreCryptoContext.clientKeypackages}
     * 3. Use these to replace the stale ones the in the backend
     * 4. Delete the stale ones locally using {@link CoreCryptoContext.deleteStaleKeyPackages}
     *      * This is the last step because you might still need the old key packages to avoid
     *        an orphan welcome message
     *
     * @param enrollment - the enrollment instance used to fetch the certificates
     * @param certificateChain - the raw response from ACME server
     * @returns Potentially a list of new crl distribution points discovered in the certificate chain
     */
    async saveX509Credential(
        enrollment: E2eiEnrollment,
        certificateChain: string
    ): Promise<NewCrlDistributionPoints> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.saveX509Credential(
                enrollment.inner(),
                certificateChain
            )
        );
    }

    /**
     * Deletes all key packages whose credential does not match the most recently
     * saved x509 credential and the provided signature scheme.
     * @param ciphersuite
     */
    async deleteStaleKeyPackages(ciphersuite: Ciphersuite): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.deleteStaleKeyPackages(ciphersuite)
        );
    }

    /**
     * Allows persisting an active enrollment (for example while redirecting the user during OAuth) in order to resume
     * it later with {@link e2eiEnrollmentStashPop}
     *
     * @param enrollment the enrollment instance to persist
     * @returns a handle to fetch the enrollment later with {@link e2eiEnrollmentStashPop}
     */
    async e2eiEnrollmentStash(enrollment: E2eiEnrollment): Promise<ArrayBuffer> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.e2eiEnrollmentStash(
                enrollment.inner()
            )
        );
    }

    /**
     * Fetches the persisted enrollment and deletes it from the keystore
     *
     * @param handle returned by {@link e2eiEnrollmentStash}
     * @returns the persisted enrollment instance
     */
    async e2eiEnrollmentStashPop(handle: ArrayBuffer): Promise<E2eiEnrollment> {
        const e2ei = await CoreCryptoError.asyncMapErr(
            this.#ctx.e2eiEnrollmentStashPop(handle)
        );
        return new E2eiEnrollment(e2ei);
    }

    /**
     * Indicates when to mark a conversation as not verified i.e. when not all its members have a X509.
     * Credential generated by Wire's end-to-end identity enrollment
     *
     * @param conversationId The group's ID
     * @returns the conversation state given current members
     */
    async e2eiConversationState(
        conversationId: ConversationId
    ): Promise<E2eiConversationState> {
        const state = await CoreCryptoError.asyncMapErr(
            this.#ctx.e2eiConversationState(conversationId)
        );

        return normalizeEnum(E2eiConversationState, state);
    }

    /**
     * Returns true when end-to-end-identity is enabled for the given Ciphersuite
     *
     * @param ciphersuite of the credential to check
     * @returns true if end-to-end identity is enabled for the given ciphersuite
     */
    async e2eiIsEnabled(ciphersuite: Ciphersuite): Promise<boolean> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.e2eiIsEnabled(ciphersuite)
        );
    }

    /**
     * From a given conversation, get the identity of the members supplied. Identity is only present for members with a
     * Certificate Credential (after turning on end-to-end identity).
     *
     * @param conversationId - identifier of the conversation
     * @param deviceIds - identifiers of the devices
     * @returns identities or if no member has a x509 certificate, it will return an empty List
     */
    async getDeviceIdentities(
        conversationId: ConversationId,
        deviceIds: ClientId[]
    ): Promise<WireIdentity[]> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.getDeviceIdentities(conversationId, deviceIds)
        );
    }

    /**
     * From a given conversation, get the identity of the users (device holders) supplied.
     * Identity is only present for devices with a Certificate Credential (after turning on end-to-end identity).
     * If no member has a x509 certificate, it will return an empty Vec.
     *
     * @param conversationId - identifier of the conversation
     * @param userIds - user identifiers hyphenated UUIDv4 e.g. 'bd4c7053-1c5a-4020-9559-cd7bf7961954'
     * @returns a Map with all the identities for a given users. Consumers are then recommended to reduce those identities to determine the actual status of a user.
     */
    async getUserIdentities(
        conversationId: ConversationId,
        userIds: string[]
    ): Promise<Map<string, WireIdentity[]>> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.getUserIdentities(conversationId, userIds)
        );
    }
}
