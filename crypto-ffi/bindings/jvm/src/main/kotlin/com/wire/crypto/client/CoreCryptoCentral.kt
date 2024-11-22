package com.wire.crypto.client

import com.wire.crypto.*
import com.wire.crypto.CoreCryptoCallbacks
import java.io.File

typealias EnrollmentHandle = ByteArray

private class Callbacks : CoreCryptoCallbacks {

    override suspend fun authorize(conversationId: ByteArray, clientId: ByteArray): Boolean = true

    override suspend fun userAuthorize(
        conversationId: ByteArray,
        externalClientId: ByteArray,
        existingClients: List<ByteArray>,
    ): Boolean = true

    override suspend fun clientIsExistingGroupUser(
        conversationId: ByteArray,
        clientId: ByteArray,
        existingClients: List<ByteArray>,
        parentConversationClients: List<ByteArray>?,
    ): Boolean = true
}

/**
 * Starts a transaction in Core Crypto. If the callback succeeds, it will be committed, otherwise,
 * every operation performed with the context will be discarded.
 *
 * @param block the function to be executed within the transaction context. A [CoreCryptoContext]
 *   will be given as parameter to this function
 * @return the return of the function passed as parameter
 */
suspend fun <R> CoreCryptoCentral.transaction(
    block: suspend (context: CoreCryptoContext) -> R
): R? {
    var result: R? = null
    var error: Throwable? = null
    try {
        this.cc.transaction(
            object : CoreCryptoCommand {
                override suspend fun execute(context: com.wire.crypto.CoreCryptoContext) {
                    try {
                        result = block(CoreCryptoContext(context))
                    } catch (e: Throwable) {
                        // We want to catch the error before it gets wrapped by core crypto.
                        error = e
                        // This is to tell core crypto that there was an error inside the
                        // transaction.
                        throw e
                    }
                }
            }
        )
        // Catch the wrapped error, which we don't need, because we caught the original error above.
    } catch (_: Throwable) {}
    if (error != null) {
        throw error as Throwable
    }
    return result
}

/**
 * Initializes the logging inside Core Crypto. Not required to be called and by default there will
 * be no logging.
 *
 * @param logger a callback to implement the platform specific logging. It will receive the string
 *   with the log text from Core Crypto
 * @param level the max level that should be logged
 */
@Deprecated("Use setLogger and setMaxLogLevel instead")
fun initLogger(logger: CoreCryptoLogger, level: CoreCryptoLogLevel) {
    com.wire.crypto.setLoggerOnly(logger)
    com.wire.crypto.setMaxLogLevel(level)
}

/**
 * Initializes the logging inside Core Crypto. Not required to be called and by default there will
 * be no logging.
 *
 * @param logger a callback to implement the platform specific logging. It will receive the string
 *   with the log text from Core Crypto
 */
fun setLogger(logger: CoreCryptoLogger) {
    com.wire.crypto.setLoggerOnly(logger)
}

/**
 * Set maximum log level of logs which are forwarded to the [CoreCryptoLogger].
 *
 * @param level the max level that should be logged, by default it will be WARN
 */
fun setMaxLogLevel(level: CoreCryptoLogLevel) {
    com.wire.crypto.setMaxLogLevel(level)
}

@Suppress("TooManyFunctions")
@OptIn(ExperimentalUnsignedTypes::class)
class CoreCryptoCentral
private constructor(internal val cc: CoreCrypto, private val rootDir: String) {
    suspend fun proteusClient(): ProteusClient = ProteusClientImpl(cc, rootDir)

    internal fun lower() = cc

    /**
     * When you have a [ClientId], use this method to initialize your [MLSClient]. If you don't have
     * a [ClientId], use [externallyGeneratedMlsClient]
     *
     * @param id client identifier
     * @param ciphersuites for which a Basic Credential has to be initialized
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun mlsClient(
        id: ClientId,
        ciphersuites: Ciphersuites = Ciphersuites.DEFAULT,
    ): MLSClient {
        return MLSClient(cc).apply { mlsInit(id, ciphersuites) }
    }

    /**
     * When you are relying on the DS to create a unique [ClientId] use this method. It will just
     * initialize the crypto backend and return a handle to continue the initialization process
     * later with [MLSClient.mlsInitWithClientId].
     *
     * @param ciphersuites for which a Basic Credential has to be initialized
     * @return a partially initialized [MLSClient] and a [ExternallyGeneratedHandle] to use in
     *   [MLSClient.mlsInitWithClientId]
     */
    @Deprecated(
        "Inside a transaction call CoreCryptoContext.mlsGenerateKeypairs() to get the handle. The CoreCryptoContext itself is a replacement for the MLSClient"
    )
    suspend fun externallyGeneratedMlsClient(
        ciphersuites: Ciphersuites = Ciphersuites.DEFAULT
    ): Pair<MLSClient, ExternallyGeneratedHandle> {
        val client = MLSClient(cc)
        val handle = client.mlsGenerateKeypairs(ciphersuites)
        return client to handle
    }

    /**
     * Creates an enrollment instance with private key material you can use in order to fetch a new
     * x509 certificate from the acme server.
     *
     * @param clientId client identifier e.g.
     *   `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
     * @param displayName human-readable name displayed in the application e.g. `Smith, Alice M
     *   (QA)`
     * @param handle user handle e.g. `alice.smith.qa@example.com`
     * @param expirySec generated x509 certificate expiry
     * @param ciphersuite for generating signing key material
     * @param team name of the Wire team a user belongs to
     * @return The new [E2EIEnrollment] enrollment to use with [e2eiMlsInitOnly]
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun e2eiNewEnrollment(
        clientId: String,
        displayName: String,
        handle: String,
        expirySec: UInt,
        ciphersuite: Ciphersuite,
        team: String? = null,
    ): E2EIEnrollment {
        return E2EIEnrollment(
            cc.e2eiNewEnrollment(
                clientId,
                displayName,
                handle,
                team,
                expirySec,
                ciphersuite.lower(),
            )
        )
    }

    /**
     * Generates an E2EI enrollment instance for a "regular" client (with a Basic credential)
     * willing to migrate to E2EI. Once the enrollment is finished, use the instance in
     * [e2eiRotateAll] to do the rotation.
     *
     * @param displayName human-readable name displayed in the application e.g. `Smith, Alice M
     *   (QA)`
     * @param handle user handle e.g. `alice.smith.qa@example.com`
     * @param expirySec generated x509 certificate expiry
     * @param ciphersuite for generating signing key material
     * @param team name of the Wire team a user belongs to
     * @return The new [E2EIEnrollment] enrollment to use with [e2eiRotateAll]
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun e2eiNewActivationEnrollment(
        displayName: String,
        handle: String,
        expirySec: UInt,
        ciphersuite: Ciphersuite,
        team: String? = null,
    ): E2EIEnrollment {
        return E2EIEnrollment(
            cc.e2eiNewActivationEnrollment(
                displayName,
                handle,
                team,
                expirySec,
                ciphersuite.lower(),
            )
        )
    }

    /**
     * Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential)
     * having to change/rotate their credential, either because the former one is expired or it has
     * been revoked. It lets you change the DisplayName or the handle if you need to. Once the
     * enrollment is finished, use the instance in [e2eiRotateAll] to do the rotation.
     *
     * @param expirySec generated x509 certificate expiry
     * @param ciphersuite for generating signing key material
     * @param displayName human-readable name displayed in the application e.g. `Smith, Alice M
     *   (QA)`
     * @param handle user handle e.g. `alice.smith.qa@example.com`
     * @param team name of the Wire team a user belongs to
     * @return The new [E2EIEnrollment] enrollment to use with [e2eiRotateAll]
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun e2eiNewRotateEnrollment(
        expirySec: UInt,
        ciphersuite: Ciphersuite,
        displayName: String? = null,
        handle: String? = null,
        team: String? = null,
    ): E2EIEnrollment {
        return E2EIEnrollment(
            cc.e2eiNewRotateEnrollment(displayName, handle, team, expirySec, ciphersuite.lower())
        )
    }

    /**
     * Use this method to initialize end-to-end identity when a client signs up and the grace period
     * is already expired ; that means he cannot initialize with a Basic credential
     *
     * @param enrollment the enrollment instance used to fetch the certificates
     * @param certificateChain the raw response from ACME server
     * @param nbKeyPackage number of initial KeyPackage to create when initializing the client
     * @return a [MLSClient] initialized with only a x509 credential
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun e2eiMlsInitOnly(
        enrollment: E2EIEnrollment,
        certificateChain: String,
        nbKeyPackage: UInt? = DEFAULT_NB_KEY_PACKAGE,
    ): Pair<MLSClient, CrlDistributionPoints?> {
        val crlsDps = cc.e2eiMlsInitOnly(enrollment.lower(), certificateChain, nbKeyPackage)
        return MLSClient(cc) to crlsDps?.toCrlDistributionPoint()
    }

    /**
     * Dumps the PKI environment as PEM
     *
     * @return a struct with different fields representing the PKI environment as PEM strings
     */
    suspend fun e2eiDumpPKIEnv(): E2eiDumpedPkiEnv? {
        return cc.e2eiDumpPkiEnv()
    }

    /** Returns whether the E2EI PKI environment is setup (i.e. Root CA, Intermediates, CRLs) */
    suspend fun e2eiIsPKIEnvSetup(): Boolean {
        return cc.e2eiIsPkiEnvSetup()
    }

    /**
     * Registers a Root Trust Anchor CA for the use in E2EI processing.
     *
     * Please note that without a Root Trust Anchor, all validations *will* fail; So this is the
     * first step to perform after initializing your E2EI client
     *
     * @param trustAnchorPEM - PEM certificate to anchor as a Trust Root
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun e2eiRegisterAcmeCA(trustAnchorPEM: String) {
        return cc.e2eiRegisterAcmeCa(trustAnchorPEM)
    }

    /**
     * Registers an Intermediate CA for the use in E2EI processing.
     *
     * Please note that a Root Trust Anchor CA is needed to validate Intermediate CAs; You **need**
     * to have a Root CA registered before calling this
     *
     * @param certPEM PEM certificate to register as an Intermediate CA
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun e2eiRegisterIntermediateCA(certPEM: String): CrlDistributionPoints? {
        return cc.e2eiRegisterIntermediateCa(certPEM)?.toCrlDistributionPoint()
    }

    /**
     * Registers a CRL for the use in E2EI processing.
     *
     * Please note that a Root Trust Anchor CA is needed to validate CRLs; You **need** to have a
     * Root CA registered before calling this
     *
     * @param crlDP CRL Distribution Point; Basically the URL you fetched it from
     * @param crlDER DER representation of the CRL
     * @return A [CrlRegistration] with the dirty state of the new CRL (see struct) and its
     *   expiration timestamp
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun e2eiRegisterCRL(crlDP: String, crlDER: ByteArray): CRLRegistration {
        return cc.e2eiRegisterCrl(crlDP, crlDER).lift()
    }

    /**
     * Creates a commit in all local conversations for changing the credential. Requires first
     * having enrolled a new X509 certificate with either [e2eiNewActivationEnrollment] or
     * []e2eiNewRotateEnrollment]
     *
     * @param enrollment the enrollment instance used to fetch the certificates
     * @param certificateChain the raw response from ACME server
     * @param newKeyPackageCount number of KeyPackages with the new identity to create
     * @return a [RotateBundle] with commits to fan-out to other group members, KeyPackages to
     *   upload and old ones to delete
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun e2eiRotateAll(
        enrollment: E2EIEnrollment,
        certificateChain: String,
        newKeyPackageCount: UInt,
    ): RotateBundle {
        return cc.e2eiRotateAll(enrollment.lower(), certificateChain, newKeyPackageCount)
            .toRotateBundle()
    }

    /**
     * Allows persisting an active enrollment (for example while redirecting the user during OAuth)
     * in order to resume it later with [e2eiEnrollmentStashPop]
     *
     * @param enrollment the enrollment instance to persist
     * @return a handle to fetch the enrollment later with [e2eiEnrollmentStashPop]
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun e2eiEnrollmentStash(enrollment: E2EIEnrollment): EnrollmentHandle {
        return cc.e2eiEnrollmentStash(enrollment.lower()).toUByteArray().asByteArray()
    }

    /**
     * Fetches the persisted enrollment and deletes it from the keystore
     *
     * @param handle returned by [e2eiEnrollmentStash]
     * @returns the persisted enrollment instance
     */
    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    suspend fun e2eiEnrollmentStashPop(handle: EnrollmentHandle): E2EIEnrollment {
        return E2EIEnrollment(cc.e2eiEnrollmentStashPop(handle))
    }

    /**
     * Closes this [CoreCryptoCentral] instance and deallocates all loaded resources.
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be usable after a call to this method,
     * but there's no way to express this requirement in Kotlin, so you'll get errors instead!
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
            ciphersuites: Ciphersuites = Ciphersuites.DEFAULT,
        ): CoreCryptoCentral {
            val path = "$rootDir/$KEYSTORE_NAME"
            File(rootDir).mkdirs()
            val cc = coreCryptoDeferredInit(path, databaseKey)
            cc.setCallbacks(Callbacks())
            return CoreCryptoCentral(cc, rootDir)
        }
    }
}
