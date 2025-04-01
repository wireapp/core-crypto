import {
    ArrayOfByteArray,
    Ciphersuite as CiphersuiteFfi,
    Ciphersuites as CiphersuitesFfi,
    ClientId as ClientIdFfi,
    ConversationConfiguration,
    CoreCryptoContext as CoreCryptoContextFfi,
    CustomConfiguration,
    E2eiDumpedPkiEnv,
    WireIdentity,
} from "./core-crypto-ffi.js";
import * as CoreCryptoFfiTypes from "./core-crypto-ffi.d.js";

import { CoreCryptoError } from "./CoreCryptoError.js";
import {
    Ciphersuite,
    ClientId,
    ConversationId,
    CredentialType,
    DecryptedMessage,
    decryptedMessageFromFfi,
    WelcomeBundle,
} from "./CoreCryptoMLS.js";

import {
    CRLRegistration,
    crlRegistrationFromFfi,
    E2eiConversationState,
    E2eiEnrollment,
    NewCrlDistributionPoints,
    normalizeEnum,
} from "./CoreCryptoE2EI.js";

import { ProteusAutoPrekeyBundle } from "./CoreCryptoProteus.js";
import { safeBigintToNumber } from "./Conversions.js";

export class CoreCryptoContext {
    /** @hidden */
    #ctx: CoreCryptoFfiTypes.CoreCryptoContext;

    /** @hidden */
    private constructor(ctx: CoreCryptoFfiTypes.CoreCryptoContext) {
        this.#ctx = ctx;
    }

    /** @hidden */
    static fromFfiContext(
        ctx: CoreCryptoFfiTypes.CoreCryptoContext
    ): CoreCryptoContext {
        return new CoreCryptoContext(ctx);
    }

    /**
     * Set arbitrary data to be retrieved by {@link getData}.
     * This is meant to be used as a check point at the end of a transaction.
     * The data should be limited to a reasonable size.
     */
    async setData(data: Uint8Array): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#ctx.set_data(data));
    }

    /**
     * Get data if it has previously been set by {@link setData}, or `undefined` otherwise.
     * This is meant to be used as a check point at the end of a transaction.
     */
    async getData(): Promise<Uint8Array | undefined> {
        return await CoreCryptoError.asyncMapErr(this.#ctx.get_data());
    }

    /**
     * Use this after {@link CoreCrypto.deferredInit} when you have a clientId. It initializes MLS.
     *
     * @param clientId - {@link CoreCryptoParams#clientId} but required
     * @param ciphersuites - All the ciphersuites supported by this MLS client
     * @param nbKeyPackage - number of initial KeyPackage to create when initializing the client
     */
    async mlsInit(
        clientId: ClientId,
        ciphersuites: Ciphersuite[],
        nbKeyPackage?: number
    ): Promise<void> {
        const id = new ClientIdFfi(clientId);
        const cs = new CiphersuitesFfi(
            Uint16Array.from(ciphersuites.map((cs) => cs.valueOf()))
        );
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.mls_init(id, cs, nbKeyPackage)
        );
    }

    /**
     * Generates a MLS KeyPair/CredentialBundle with a temporary, random client ID.
     * This method is designed to be used in conjunction with {@link CoreCryptoContext.mlsInitWithClientId} and represents the first step in this process
     *
     * @param ciphersuites - All the ciphersuites supported by this MLS client
     * @returns This returns the TLS-serialized identity key (i.e. the signature keypair's public key)
     */
    async mlsGenerateKeypair(
        ciphersuites: Ciphersuite[]
    ): Promise<Uint8Array[]> {
        const cs = new CiphersuitesFfi(
            Uint16Array.from(ciphersuites.map((cs) => cs.valueOf()))
        );
        const kps = await CoreCryptoError.asyncMapErr(
            this.#ctx.mls_generate_keypairs(cs)
        );
        return kps.map((kp) => kp.as_bytes());
    }

    /**
     * Updates the current temporary Client ID with the newly provided one. This is the second step in the externally-generated clients process
     *
     * Important: This is designed to be called after {@link CoreCryptoContext.mlsGenerateKeypair}
     *
     * @param clientId - The newly-allocated client ID by the MLS Authentication Service
     * @param signaturePublicKeys - The public key you were given at the first step; This is for authentication purposes
     * @param ciphersuites - All the ciphersuites supported by this MLS client
     */
    async mlsInitWithClientId(
        clientId: ClientId,
        signaturePublicKeys: Uint8Array[],
        ciphersuites: Ciphersuite[]
    ): Promise<void> {
        const id = new ClientIdFfi(clientId);
        const pks = signaturePublicKeys.map((pk) => new ClientIdFfi(pk));
        const cs = new CiphersuitesFfi(
            Uint16Array.from(ciphersuites.map((cs) => cs.valueOf()))
        );
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.mls_init_with_client_id(id, pks, cs)
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
            this.#ctx.conversation_exists(conversationId)
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
            this.#ctx.mark_conversation_as_child_of(childId, parentId)
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
            this.#ctx.conversation_epoch(conversationId)
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
            this.#ctx.conversation_ciphersuite(conversationId)
        );
        return cs.as_u16();
    }

    /**
     * Wipes and destroys the local storage of a given conversation / MLS group
     *
     * @param conversationId - The ID of the conversation to remove
     */
    async wipeConversation(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.wipe_conversation(conversationId)
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
     * @param configuration.custom - {@link CustomConfiguration}
     */
    async createConversation(
        conversationId: ConversationId,
        creatorCredentialType: CredentialType,
        configuration: Partial<ConversationConfiguration> = {}
    ) {
        const { ciphersuite, externalSenders, custom } = configuration;
        const config = new ConversationConfiguration(
            ciphersuite,
            externalSenders,
            custom?.keyRotationSpan,
            custom?.wirePolicy
        );
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.create_conversation(
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
        payload: Uint8Array
    ): Promise<DecryptedMessage> {
        if (!payload?.length) {
            throw new Error("decryptMessage payload is empty or null");
        }

        const ffiDecryptedMessage = await CoreCryptoError.asyncMapErr(
            this.#ctx.decrypt_message(conversationId, payload)
        );

        return decryptedMessageFromFfi(ffiDecryptedMessage);
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
        message: Uint8Array
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.encrypt_message(conversationId, message)
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
        welcomeMessage: Uint8Array,
        configuration: Partial<CustomConfiguration> = {}
    ): Promise<WelcomeBundle> {
        const { keyRotationSpan, wirePolicy } = configuration || {};
        const config = new CustomConfiguration(keyRotationSpan, wirePolicy);
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.process_welcome_message(welcomeMessage, config)
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
    ): Promise<Uint8Array> {
        const cs = new CiphersuiteFfi(ciphersuite);
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.client_public_key(cs, credentialType)
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
        const cs = new CiphersuiteFfi(ciphersuite);
        const kpCount = await CoreCryptoError.asyncMapErr(
            this.#ctx.client_valid_keypackages_count(cs, credentialType)
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
    ): Promise<Array<Uint8Array>> {
        const cs = new CiphersuiteFfi(ciphersuite);
        const kps = await CoreCryptoError.asyncMapErr(
            this.#ctx.client_keypackages(cs, credentialType, amountRequested)
        );
        return kps.as_arrays();
    }

    /**
     * Prunes local KeyPackages after making sure they also have been deleted on the backend side
     * You should only use this after calling {@link CoreCryptoContext.e2eiRotate} on all conversations.
     *
     * @param refs - KeyPackage references to delete obtained from a {RotateBundle}
     */
    async deleteKeypackages(refs: Uint8Array[]): Promise<void> {
        const aobaRefs = new ArrayOfByteArray(refs);
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.delete_keypackages(aobaRefs)
        );
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
        keyPackages: Uint8Array[]
    ): Promise<NewCrlDistributionPoints> {
        const kps = new ArrayOfByteArray(keyPackages);
        const dps = await CoreCryptoError.asyncMapErr(
            this.#ctx.add_clients_to_conversation(conversationId, kps)
        );
        return dps.as_strings();
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
        const ids = clientIds.map((id) => new ClientIdFfi(id));
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.remove_clients_from_conversation(conversationId, ids)
        );
    }

    /**
     * Update the keying material of the conversation.
     *
     * @param conversationId - The ID of the conversation
     */
    async updateKeyingMaterial(conversationId: ConversationId): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.update_keying_material(conversationId)
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
            this.#ctx.commit_pending_proposals(conversationId)
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
        groupInfo: Uint8Array,
        credentialType: CredentialType,
        configuration: Partial<CustomConfiguration> = {}
    ): Promise<WelcomeBundle> {
        const { keyRotationSpan, wirePolicy } = configuration || {};
        const config = new CustomConfiguration(keyRotationSpan, wirePolicy);
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.join_by_external_commit(groupInfo, config, credentialType)
        );
    }

    /**
     * Derives a new key from the group
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
            this.#ctx.export_secret_key(conversationId, keyLength)
        );
    }

    /**
     * Returns the raw public key of the single external sender present in this group.
     * This should be used to initialize a subconversation
     *
     * @param conversationId - The group's ID
     *
     * @returns A `Uint8Array` representing the external sender raw public key
     */
    async getExternalSender(
        conversationId: ConversationId
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.get_external_sender(conversationId)
        );
    }

    /**
     * Returns all clients from group's members
     *
     * @param conversationId - The group's ID
     *
     * @returns A list of clients from the members of the group
     */
    async getClientIds(conversationId: ConversationId): Promise<ClientId[]> {
        const ids = await CoreCryptoError.asyncMapErr(
            this.#ctx.get_client_ids(conversationId)
        );
        return ids.map((id) => id.as_bytes());
    }

    /**
     * Allows {@link CoreCryptoContext} to act as a CSPRNG provider
     *
     * The underlying CSPRNG algorithm is ChaCha20 and takes in account the external seed provider.
     *
     * @param length - The number of bytes to be returned in the `Uint8Array`
     *
     * @returns A `Uint8Array` buffer that contains `length` cryptographically-secure random bytes
     */
    async randomBytes(length: number): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.random_bytes(length)
        );
    }

    /**
     * Initializes the proteus client
     */
    async proteusInit(): Promise<void> {
        return await CoreCryptoError.asyncMapErr(this.#ctx.proteus_init());
    }

    /**
     * Create a Proteus session using a prekey
     *
     * @param sessionId - ID of the Proteus session
     * @param prekey - CBOR-encoded Proteus prekey of the other client
     */
    async proteusSessionFromPrekey(
        sessionId: string,
        prekey: Uint8Array
    ): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteus_session_from_prekey(sessionId, prekey)
        );
    }

    /**
     * Create a Proteus session from a handshake message
     *
     * @param sessionId - ID of the Proteus session
     * @param envelope - CBOR-encoded Proteus message
     *
     * @returns A `Uint8Array` containing the message that was sent along with the session handshake
     */
    async proteusSessionFromMessage(
        sessionId: string,
        envelope: Uint8Array
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteus_session_from_message(sessionId, envelope)
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
            this.#ctx.proteus_session_save(sessionId)
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
            this.#ctx.proteus_session_delete(sessionId)
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
            this.#ctx.proteus_session_exists(sessionId)
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
        ciphertext: Uint8Array
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteus_decrypt(sessionId, ciphertext)
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
        plaintext: Uint8Array
    ): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteus_encrypt(sessionId, plaintext)
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
        plaintext: Uint8Array
    ): Promise<Map<string, Uint8Array>> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteus_encrypt_batched(sessions, plaintext)
        );
    }

    /**
     * Creates a new prekey with the requested ID.
     *
     * @param prekeyId - ID of the PreKey to generate. This cannot be bigger than a u16
     * @returns: A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey
     */
    async proteusNewPrekey(prekeyId: number): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteus_new_prekey(prekeyId)
        );
    }

    /**
     * Creates a new prekey with an automatically generated ID..
     *
     * @returns A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey accompanied by its ID
     */
    async proteusNewPrekeyAuto(): Promise<ProteusAutoPrekeyBundle> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteus_new_prekey_auto()
        );
    }

    /**
     * Proteus last resort prekey stuff
     *
     * @returns A CBOR-serialize version of the PreKeyBundle associated with the last resort PreKey (holding the last resort prekey id)
     */
    async proteusLastResortPrekey(): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteus_last_resort_prekey()
        );
    }

    /**
     * @returns The last resort PreKey id
     */
    static proteusLastResortPrekeyId(): number {
        return CoreCryptoContextFfi.proteus_last_resort_prekey_id();
    }

    /**
     * Proteus public key fingerprint
     * It's basically the public key encoded as an hex string
     *
     * @returns Hex-encoded public key string
     */
    async proteusFingerprint(): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteus_fingerprint()
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
            this.#ctx.proteus_fingerprint_local(sessionId)
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
            this.#ctx.proteus_fingerprint_remote(sessionId)
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
            return CoreCryptoContextFfi.proteus_fingerprint_prekeybundle(
                prekey
            );
        } catch (e) {
            throw CoreCryptoError.fromStdError(e as Error);
        }
    }

    /**
     * Imports all the data stored by Cryptobox into the CoreCrypto keystore
     *
     * @param storeName - The name of the IndexedDB store where the data is stored
     */
    async proteusCryptoboxMigrate(storeName: string): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.proteus_cryptobox_migrate(storeName)
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
        const cs = new CiphersuiteFfi(ciphersuite);
        const e2ei = await CoreCryptoError.asyncMapErr(
            this.#ctx.e2ei_new_enrollment(
                clientId,
                displayName,
                handle,
                team,
                expirySec,
                cs
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
        const cs = new CiphersuiteFfi(ciphersuite);
        const e2ei = await CoreCryptoError.asyncMapErr(
            this.#ctx.e2ei_new_activation_enrollment(
                displayName,
                handle,
                team,
                expirySec,
                cs
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
        const cs = new CiphersuiteFfi(ciphersuite);
        const e2ei = await CoreCryptoError.asyncMapErr(
            this.#ctx.e2ei_new_rotate_enrollment(
                displayName,
                handle,
                team,
                expirySec,
                cs
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
     * @param nbKeyPackage - number of initial KeyPackage to create when initializing the client
     * @returns a MlsClient initialized with only a x509 credential
     */
    async e2eiMlsInitOnly(
        enrollment: E2eiEnrollment,
        certificateChain: string,
        nbKeyPackage?: number
    ): Promise<NewCrlDistributionPoints> {
        const dps = await this.#ctx.e2ei_mls_init_only(
            enrollment.inner() as CoreCryptoFfiTypes.FfiWireE2EIdentity,
            certificateChain,
            nbKeyPackage
        );
        return dps.as_strings();
    }

    /**
     * Dumps the PKI environment as PEM
     *
     * @returns a struct with different fields representing the PKI environment as PEM strings
     */
    async e2eiDumpPKIEnv(): Promise<E2eiDumpedPkiEnv | undefined> {
        return await this.#ctx.e2ei_dump_pki_env();
    }

    /**
     * @returns whether the E2EI PKI environment is setup (i.e. Root CA, Intermediates, CRLs)
     */
    async e2eiIsPKIEnvSetup(): Promise<boolean> {
        return await this.#ctx.e2ei_is_pki_env_setup();
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
        return await this.#ctx.e2ei_register_acme_ca(trustAnchorPEM);
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
        const dps = await this.#ctx.e2ei_register_intermediate_ca(certPEM);
        return dps.as_strings();
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
        crlDER: Uint8Array
    ): Promise<CRLRegistration> {
        const reg = await this.#ctx.e2ei_register_crl(crlDP, crlDER);
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
            this.#ctx.e2ei_rotate(conversationId)
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
        const dps = await CoreCryptoError.asyncMapErr(
            this.#ctx.save_x509_credential(
                enrollment.inner() as CoreCryptoFfiTypes.FfiWireE2EIdentity,
                certificateChain
            )
        );
        return dps.as_strings();
    }

    /**
     * Deletes all key packages whose credential does not match the most recently
     * saved x509 credential and the provided signature scheme.
     * @param cipherSuite
     */
    async deleteStaleKeyPackages(cipherSuite: Ciphersuite): Promise<void> {
        const cs = new CiphersuiteFfi(cipherSuite);
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.delete_stale_key_packages(cs)
        );
    }

    /**
     * Allows persisting an active enrollment (for example while redirecting the user during OAuth) in order to resume
     * it later with {@link e2eiEnrollmentStashPop}
     *
     * @param enrollment the enrollment instance to persist
     * @returns a handle to fetch the enrollment later with {@link e2eiEnrollmentStashPop}
     */
    async e2eiEnrollmentStash(enrollment: E2eiEnrollment): Promise<Uint8Array> {
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.e2ei_enrollment_stash(
                enrollment.inner() as CoreCryptoFfiTypes.FfiWireE2EIdentity
            )
        );
    }

    /**
     * Fetches the persisted enrollment and deletes it from the keystore
     *
     * @param handle returned by {@link e2eiEnrollmentStash}
     * @returns the persisted enrollment instance
     */
    async e2eiEnrollmentStashPop(handle: Uint8Array): Promise<E2eiEnrollment> {
        const e2ei = await CoreCryptoError.asyncMapErr(
            this.#ctx.e2ei_enrollment_stash_pop(handle)
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
            this.#ctx.e2ei_conversation_state(conversationId)
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
        const cs = new CiphersuiteFfi(ciphersuite);
        return await CoreCryptoError.asyncMapErr(this.#ctx.e2ei_is_enabled(cs));
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
        const dids = deviceIds.map((did) => new ClientIdFfi(did));
        return await CoreCryptoError.asyncMapErr(
            this.#ctx.get_device_identities(conversationId, dids)
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
            this.#ctx.get_user_identities(conversationId, userIds)
        );
    }

    /**
     * Gets the e2ei conversation state from a `GroupInfo`. Useful to check if the group has e2ei
     * turned on or not before joining it.
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
            this.#ctx.get_credential_in_use(groupInfo, credentialType)
        );
        return normalizeEnum(E2eiConversationState, state);
    }
}
