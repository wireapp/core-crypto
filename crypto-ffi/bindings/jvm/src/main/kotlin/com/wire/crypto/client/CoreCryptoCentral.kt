package com.wire.crypto.client

import com.wire.crypto.*
import java.io.File

typealias EnrollmentHandle = ByteArray

private class Callbacks : CoreCryptoCallbacks {

    override fun authorize(conversationId: ByteArray, clientId: ByteArray): Boolean = true

    override fun userAuthorize(
        conversationId: ByteArray,
        externalClientId: ByteArray,
        existingClients: List<ByteArray>
    ): Boolean = true

    override fun clientIsExistingGroupUser(
        conversationId: ByteArray,
        clientId: ByteArray,
        existingClients: List<ByteArray>,
        parentConversationClients: List<ByteArray>?
    ): Boolean = true
}

@Suppress("TooManyFunctions")
@OptIn(ExperimentalUnsignedTypes::class)
class CoreCryptoCentral private constructor(private val cc: CoreCrypto, private val rootDir: String) {
    suspend fun proteusClient(): ProteusClient = ProteusClientImpl(cc, rootDir)

    internal fun lower() = cc

    /**
     * When you have a [ClientId], use this method to initialize your [MLSClient].
     * If you don't have a [ClientId], use [externallyGeneratedMlsClient]
     *
     * @param id client identifier
     * @param ciphersuites for which a Basic Credential has to be initialized
     */
    suspend fun mlsClient(id: ClientId, ciphersuites: Ciphersuites = Ciphersuites.DEFAULT): MLSClient {
        return MLSClient(cc).apply { mlsInit(id, ciphersuites) }
    }

    /**
     * When you are relying on the DS to create a unique [ClientId] use this method.
     * It will just initialize the crypto backend and return a handle to continue the initialization process later with
     * [MLSClient.mlsInitWithClientId].
     *
     * @param ciphersuites for which a Basic Credential has to be initialized
     * @return a partially initialized [MLSClient] and a [ExternallyGeneratedHandle] to use in [MLSClient.mlsInitWithClientId]
     */
    suspend fun externallyGeneratedMlsClient(ciphersuites: Ciphersuites = Ciphersuites.DEFAULT): Pair<MLSClient, ExternallyGeneratedHandle> {
        val client = MLSClient(cc)
        val handle = client.mlsGenerateKeypairs(ciphersuites)
        return client to handle
    }

    /**
     * Creates an enrollment instance with private key material you can use in order to fetch a new x509 certificate from the acme server.
     *
     * @param clientId client identifier e.g. `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
     * @param displayName human-readable name displayed in the application e.g. `Smith, Alice M (QA)`
     * @param handle user handle e.g. `alice.smith.qa@example.com`
     * @param expiryDays generated x509 certificate expiry
     * @param ciphersuite for generating signing key material
     * @param team name of the Wire team a user belongs to
     * @return The new [E2EIEnrollment] enrollment to use with [e2eiMlsInitOnly]
     */
    suspend fun e2eiNewEnrollment(
        clientId: String,
        displayName: String,
        handle: String,
        expiryDays: UInt,
        ciphersuite: Ciphersuite,
        team: String? = null,
    ): E2EIEnrollment {
        return E2EIEnrollment(cc.e2eiNewEnrollment(clientId, displayName, handle, team, expiryDays, ciphersuite.lower()))
    }

    /**
     * Generates an E2EI enrollment instance for a "regular" client (with a Basic credential) willing to migrate to E2EI.
     * Once the enrollment is finished, use the instance in [e2eiRotateAll] to do the rotation.
     *
     * @param displayName human-readable name displayed in the application e.g. `Smith, Alice M (QA)`
     * @param handle user handle e.g. `alice.smith.qa@example.com`
     * @param expiryDays generated x509 certificate expiry
     * @param ciphersuite for generating signing key material
     * @param team name of the Wire team a user belongs to
     * @return The new [E2EIEnrollment] enrollment to use with [e2eiRotateAll]
     */
    suspend fun e2eiNewActivationEnrollment(
        displayName: String,
        handle: String,
        expiryDays: UInt,
        ciphersuite: Ciphersuite,
        team: String? = null,
    ): E2EIEnrollment {
        return E2EIEnrollment(
            cc.e2eiNewActivationEnrollment(
                displayName,
                handle,
                team,
                expiryDays,
                ciphersuite.lower()
            )
        )
    }

    /**
     * Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential) having to change/rotate
     * their credential, either because the former one is expired or it has been revoked. It lets you change the DisplayName
     * or the handle if you need to. Once the enrollment is finished, use the instance in [e2eiRotateAll] to do the rotation.
     *
     * @param expiryDays generated x509 certificate expiry
     * @param ciphersuite for generating signing key material
     * @param displayName human-readable name displayed in the application e.g. `Smith, Alice M (QA)`
     * @param handle user handle e.g. `alice.smith.qa@example.com`
     * @param team name of the Wire team a user belongs to
     * @return The new [E2EIEnrollment] enrollment to use with [e2eiRotateAll]
     */
    suspend fun e2eiNewRotateEnrollment(
        expiryDays: UInt,
        ciphersuite: Ciphersuite,
        displayName: String? = null,
        handle: String? = null,
        team: String? = null,
    ): E2EIEnrollment {
        return E2EIEnrollment(
            cc.e2eiNewRotateEnrollment(
                displayName,
                handle,
                team,
                expiryDays,
                ciphersuite.lower()
            )
        )
    }

    /**
     * Use this method to initialize end-to-end identity when a client signs up and the grace period is already expired ;
     * that means he cannot initialize with a Basic credential
     *
     * @param enrollment the enrollment instance used to fetch the certificates
     * @param certificateChain the raw response from ACME server
     * @param nbKeyPackage number of initial KeyPackage to create when initializing the client
     * @return a [MLSClient] initialized with only a x509 credential
     */
    suspend fun e2eiMlsInitOnly(enrollment: E2EIEnrollment, certificateChain: String, nbKeyPackage: UInt? = DEFAULT_NB_KEY_PACKAGE): MLSClient {
        cc.e2eiMlsInitOnly(enrollment.lower(), certificateChain, nbKeyPackage)
        return MLSClient(cc)
    }

    /**
    * Registers a Root Trust Anchor CA for the use in E2EI processing.
    *
    * Please note that without a Root Trust Anchor, all validations *will* fail;
    * So this is the first step to perform after initializing your E2EI client
    *
    * @param trustAnchorPEM - PEM certificate to anchor as a Trust Root
    */
    suspend fun e2eiRegisterAcmeCA(trustAnchorPEM: String) {
        return cc.e2eiRegisterAcmeCa(trustAnchorPEM)
    }


    /**
    * Registers an Intermediate CA for the use in E2EI processing.
    *
    * Please note that a Root Trust Anchor CA is needed to validate Intermediate CAs;
    * You **need** to have a Root CA registered before calling this
    *
    * @param certPEM PEM certificate to register as an Intermediate CA
    */
    suspend fun e2eiRegisterIntermediateCA(certPEM: String) {
        return cc.e2eiRegisterIntermediateCa(certPEM)
    }


    /**
    * Registers a CRL for the use in E2EI processing.
    *
    * Please note that a Root Trust Anchor CA is needed to validate CRLs;
    * You **need** to have a Root CA registered before calling this
    *
    * @param crlDP CRL Distribution Point; Basically the URL you fetched it from
    * @param crlDER DER representation of the CRL
    * @return A [CrlRegistration] with the dirty state of the new CRL (see struct) and its expiration timestamp
    */
    suspend fun e2eiRegisterCRL(crlDP: String, crlDER: ByteArray): CRLRegistration {
        return cc.e2eiRegisterCrl(crlDP, crlDER).lift()
    }

    /**
     * Creates a commit in all local conversations for changing the credential. Requires first having enrolled a new X509
     * certificate with either [e2eiNewActivationEnrollment] or []e2eiNewRotateEnrollment]
     *
     * @param enrollment the enrollment instance used to fetch the certificates
     * @param certificateChain the raw response from ACME server
     * @param newKeyPackageCount number of KeyPackages with the new identity to create
     * @return a [RotateBundle] with commits to fan-out to other group members, KeyPackages to upload and old ones to delete
     */
    suspend fun e2eiRotateAll(
        enrollment: E2EIEnrollment,
        certificateChain: String,
        newKeyPackageCount: UInt
    ): RotateBundle {
        return cc.e2eiRotateAll(enrollment.lower(), certificateChain, newKeyPackageCount).toRotateBundle()
    }

    /**
     * Allows persisting an active enrollment (for example while redirecting the user during OAuth) in order to resume
     * it later with [e2eiEnrollmentStashPop]
     *
     * @param enrollment the enrollment instance to persist
     * @return a handle to fetch the enrollment later with [e2eiEnrollmentStashPop]
     */
    suspend fun e2eiEnrollmentStash(enrollment: E2EIEnrollment): EnrollmentHandle {
        return cc.e2eiEnrollmentStash(enrollment.lower()).toUByteArray().asByteArray()
    }

    /**
     * Fetches the persisted enrollment and deletes it from the keystore
     *
     * @param handle returned by [e2eiEnrollmentStash]
     * @returns the persisted enrollment instance
     */
    suspend fun e2eiEnrollmentStashPop(handle: EnrollmentHandle): E2EIEnrollment {
        return E2EIEnrollment(cc.e2eiEnrollmentStashPop(handle))
    }

    /**
     * Closes this [CoreCryptoCentral] instance and deallocates all loaded resources.
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be usable after a call to this method, but there's no way to express this requirement in Kotlin, so you'll get errors instead!
     */
    suspend fun close() {
        cc.close()
    }

    companion object {
        private const val KEYSTORE_NAME = "keystore"
        internal const val DEFAULT_NB_KEY_PACKAGE: UInt = 100U

        suspend operator fun invoke(
            rootDir: String,
            databaseKey: String,
            ciphersuites: Ciphersuites = Ciphersuites.DEFAULT
        ): CoreCryptoCentral {
            val path = "$rootDir/$KEYSTORE_NAME"
            File(rootDir).mkdirs()
            val cc = coreCryptoDeferredInit(path, databaseKey, ciphersuites.lower(), DEFAULT_NB_KEY_PACKAGE)
            cc.setCallbacks(Callbacks())
            return CoreCryptoCentral(cc, rootDir)
        }
    }
}

