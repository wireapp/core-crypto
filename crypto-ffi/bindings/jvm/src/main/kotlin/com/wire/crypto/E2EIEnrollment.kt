package com.wire.crypto

typealias JsonRawData = ByteArray

/**
 * E2eiDumpedPkiEnv
 * @property rootCa root CA
 * @property intermediates intermediates
 * @property crls CRLs
 */
data class E2eiDumpedPkiEnv(
    var rootCa: String,
    var intermediates: List<String>,
    var crls: List<String>
)

internal fun com.wire.crypto.uniffi.E2eiDumpedPkiEnv.lift() =
    E2eiDumpedPkiEnv(
        rootCa = rootCa,
        intermediates = intermediates,
        crls = crls
    )

/** Supporting struct for CRL registration result */
data class CRLRegistration(
    /** Whether this CRL modifies the old CRL (i.e. has a different revocated cert list) */
    val dirty: Boolean,
    /** Optional expiration timestamp */
    val expiration: Long?,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CRLRegistration

        if (dirty != other.dirty) return false
        if (expiration != other.expiration) return false

        return true
    }

    override fun hashCode(): Int {
        var result = dirty.hashCode()
        result = 31 * result + (expiration?.hashCode() ?: 0)
        return result
    }
}

internal fun com.wire.crypto.uniffi.CrlRegistration.lift() = CRLRegistration(dirty, expiration?.toLong())

/** AcmeDirectory */
data class AcmeDirectory(private val delegate: com.wire.crypto.uniffi.AcmeDirectory) {
    /** newNonce */
    val newNonce: String
        get() = delegate.newNonce

    /** newOrder */
    val newOrder: String
        get() = delegate.newOrder

    /** newAccount */
    val newAccount: String
        get() = delegate.newAccount

    /** revokeCert */
    val revokeCert: String
        get() = delegate.revokeCert

    private fun lower() = delegate
}

private fun com.wire.crypto.uniffi.AcmeDirectory.toAcmeDirectory() = AcmeDirectory(this)

/** NewAcmeOrder */
@OptIn(ExperimentalUnsignedTypes::class)
data class NewAcmeOrder(private val delegate: com.wire.crypto.uniffi.NewAcmeOrder) {
    /** authorizations */
    val authorizations: List<String>
        get() = delegate.authorizations

    /** raw */
    val raw: JsonRawData
        get() = delegate.delegate.toUByteArray().asByteArray()

    private fun lower() = delegate
}

private fun com.wire.crypto.uniffi.NewAcmeOrder.toNewAcmeOrder() = NewAcmeOrder(this)

/** AcmeChallenge */
@OptIn(ExperimentalUnsignedTypes::class)
data class AcmeChallenge(private val delegate: com.wire.crypto.uniffi.AcmeChallenge) {
    /** url */
    val url: String
        get() = delegate.url

    /** target */
    val target: String
        get() = delegate.target

    /** raw */
    val raw: JsonRawData
        get() = delegate.delegate.toUByteArray().asByteArray()

    private fun lower() = delegate
}

private fun com.wire.crypto.uniffi.AcmeChallenge.toAcmeChallenge() = AcmeChallenge(this)

/** NewAcmeAuthz */
data class NewAcmeAuthz(private val delegate: com.wire.crypto.uniffi.NewAcmeAuthz) {
    /** identifier */
    val identifier: String
        get() = delegate.identifier

    /** keyauth */
    val keyauth: String?
        get() = delegate.keyauth

    /** challenge */
    val challenge: AcmeChallenge
        get() = delegate.challenge.toAcmeChallenge()

    private fun lower() = delegate
}

private fun com.wire.crypto.uniffi.NewAcmeAuthz.toNewAcmeAuthz() = NewAcmeAuthz(this)

/** Represents an E2EI enrollment */
@Suppress("TooManyFunctions")
class E2EIEnrollment(private val delegate: com.wire.crypto.uniffi.E2eiEnrollment) {
    internal fun lower() = delegate

    /**
     * Parses the response from `GET /acme/{provisioner-name}/directory`. Use this [AcmeDirectory]
     * in the next step to fetch the first nonce from the acme server. Use [AcmeDirectory.newNonce].
     *
     * @param directory HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
     */
    suspend fun directoryResponse(directory: JsonRawData) =
        delegate.directoryResponse(directory).toAcmeDirectory()

    /**
     * For creating a new acme account. This returns a signed JWS-alike request body to send to
     * `POST /acme/{provisioner-name}/new-account`.
     *
     * @param previousNonce you got from calling `HEAD [AcmeDirectory.newNonce]`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
     */
    suspend fun newAccountRequest(previousNonce: String) = delegate.newAccountRequest(previousNonce)

    /**
     * Parses the response from `POST /acme/{provisioner-name}/new-account`.
     *
     * @param account HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
     */
    suspend fun accountResponse(account: JsonRawData) = delegate.newAccountResponse(account)

    /**
     * Creates a new acme order for the handle (userId + display name) and the clientId.
     *
     * @param previousNonce `replay-nonce` response header from `POST
     *   /acme/{provisioner-name}/new-account`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    suspend fun newOrderRequest(previousNonce: String) = delegate.newOrderRequest(previousNonce)

    /**
     * Parses the response from `POST /acme/{provisioner-name}/new-order`.
     *
     * @param order HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    suspend fun newOrderResponse(order: JsonRawData) =
        delegate.newOrderResponse(order).toNewAcmeOrder()

    /**
     * Creates a new authorization request.
     *
     * @param url one of the URL in new order's authorizations (use [NewAcmeOrder.authorizations]
     *   from [newOrderResponse])
     * @param previousNonce `replay-nonce` response header from `POST
     *   /acme/{provisioner-name}/new-order` (or from the previous to this method if you are
     *   creating the second authorization)
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
     */
    suspend fun newAuthzRequest(url: String, previousNonce: String) =
        delegate.newAuthzRequest(url, previousNonce)

    /**
     * Parses the response from `POST /acme/{provisioner-name}/authz/{authz-id}`
     *
     * @param authz HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
     */
    suspend fun authzResponse(authz: JsonRawData) =
        delegate.newAuthzResponse(authz).toNewAcmeAuthz()

    /**
     * Generates a new client Dpop JWT token. It demonstrates proof of possession of the nonces
     * (from wire-server & acme server) and will be verified by the acme server when verifying the
     * challenge (in order to deliver a certificate).
     *
     * Then send it to
     * [`POST /clients/{id}/access-token`](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
     * on wire-server.
     *
     * @param expirySecs of the client Dpop JWT. This should be equal to the grace period set in
     *   Team Management
     * @param backendNonce you get by calling `GET /clients/token/nonce` on wire-server as defined
     *   here {@link
     *   https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/get_clients__client__nonce}
     */
    suspend fun createDpopToken(expirySecs: UInt, backendNonce: String) =
        delegate.createDpopToken(expirySecs, backendNonce)

    /**
     * Creates a new challenge request for Wire Dpop challenge.
     *
     * @param accessToken returned by wire-server from
     *   https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token
     * @param previousNonce `replay-nonce` response header from `POST
     *   /acme/{provisioner-name}/authz/{authz-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    suspend fun newDpopChallengeRequest(accessToken: String, previousNonce: String) =
        delegate.newDpopChallengeRequest(accessToken, previousNonce)

    /**
     * Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for DPoP
     * challenge.
     *
     * @param challenge HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    suspend fun dpopChallengeResponse(challenge: JsonRawData) =
        delegate.newDpopChallengeResponse(challenge)

    /**
     * Creates a new challenge request for Wire Oidc challenge.
     *
     * @param idToken you get back from Identity Provider
     * @param previousNonce `replay-nonce` response header from `POST
     *   /acme/{provisioner-name}/authz/{authz-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    suspend fun newOidcChallengeRequest(
        idToken: String,
        previousNonce: String,
    ) = delegate.newOidcChallengeRequest(idToken, previousNonce)

    /**
     * Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for OIDC
     * challenge within a CoreCryptoContext.
     *
     * @param challenge HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    suspend fun contextOidcChallengeResponse(challenge: JsonRawData) =
        delegate.newOidcChallengeResponse(challenge)

    /**
     * Verifies that the previous challenge has been completed.
     *
     * @param orderUrl `location` header from http response you got from [newOrderResponse]
     * @param previousNonce `replay-nonce` response header from `POST
     *   /acme/{provisioner-name}/challenge/{challenge-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    suspend fun checkOrderRequest(orderUrl: String, previousNonce: String) =
        delegate.checkOrderRequest(orderUrl, previousNonce)

    /**
     * Parses the response from `POST /acme/{provisioner-name}/order/{order-id}`.
     *
     * @param order HTTP response body
     * @return finalize url to use with [finalizeRequest]
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    suspend fun checkOrderResponse(order: JsonRawData) = delegate.checkOrderResponse(order)

    /**
     * Final step before fetching the certificate.
     *
     * @param previousNonce - `replay-nonce` response header from `POST
     *   /acme/{provisioner-name}/order/{order-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    suspend fun finalizeRequest(previousNonce: String) = delegate.finalizeRequest(previousNonce)

    /**
     * Parses the response from `POST /acme/{provisioner-name}/order/{order-id}/finalize`.
     *
     * @param finalize HTTP response body
     * @return the certificate url to use with [certificateRequest]
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    suspend fun finalizeResponse(finalize: JsonRawData) = delegate.finalizeResponse(finalize)

    /**
     * Creates a request for finally fetching the x509 certificate.
     *
     * @param previousNonce `replay-nonce` response header from `POST
     *   /acme/{provisioner-name}/order/{order-id}/finalize`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2
     */
    suspend fun certificateRequest(previousNonce: String) =
        delegate.certificateRequest(previousNonce)
}
