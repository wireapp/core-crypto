package com.wire.crypto.client

import com.wire.crypto.WireE2eIdentity
import com.wire.crypto.CommitBundle
import com.wire.crypto.client.AcmeChallenge.Companion.toAcmeChallenge
import com.wire.crypto.client.AcmeDirectory.Companion.toAcmeDirectory
import com.wire.crypto.client.NewAcmeAuthz.Companion.toNewAcmeAuthz
import com.wire.crypto.client.NewAcmeOrder.Companion.toNewAcmeOrder

typealias JsonRawData = ByteArray
typealias DpopToken = String

data class RotateBundle(
    val commits: HashMap<String, CommitBundle>,
    val newKeyPackages: List<ByteArray>,
    val keyPackageRefsToRemove: List<ByteArray>,
)

data class AcmeDirectory(
    val newNonce: String,
    val newAccount: String,
    val newOrder: String
) {
    constructor(delegate: com.wire.crypto.AcmeDirectory) : this(
        delegate.newNonce,
        delegate.newAccount,
        delegate.newOrder
    )

    companion object {
        fun com.wire.crypto.AcmeDirectory.toAcmeDirectory() = AcmeDirectory(this)
    }
}

data class NewAcmeOrder(val delegate: JsonRawData, val authorizations: List<String>) {

    @OptIn(ExperimentalUnsignedTypes::class)
    constructor(delegate: com.wire.crypto.NewAcmeOrder) : this(
        delegate.delegate.toUByteArray().asByteArray(),
        delegate.authorizations,
    )

    companion object {
        fun com.wire.crypto.NewAcmeOrder.toNewAcmeOrder() = NewAcmeOrder(this)
    }
}

data class AcmeChallenge(val delegate: JsonRawData, val url: String) {
    @OptIn(ExperimentalUnsignedTypes::class)
    constructor(delegate: com.wire.crypto.AcmeChallenge) : this(
        delegate.delegate.toUByteArray().asByteArray(), delegate.url
    )

    companion object {
        fun com.wire.crypto.AcmeChallenge.toAcmeChallenge() = AcmeChallenge(this)
    }
}

data class NewAcmeAuthz(
    val identifier: String,
    val wireOidcChallenge: AcmeChallenge?,
    val wireDpopChallenge: AcmeChallenge?
) {
    constructor(delegate: com.wire.crypto.NewAcmeAuthz) : this(
        delegate.identifier,
        delegate.wireOidcChallenge?.toAcmeChallenge(),
        delegate.wireDpopChallenge?.toAcmeChallenge(),
    )

    companion object {
        fun com.wire.crypto.NewAcmeAuthz.toNewAcmeAuthz() = NewAcmeAuthz(this)
    }
}

@Suppress("TooManyFunctions")
interface E2EIClient {
    val delegate: WireE2eIdentity
    suspend fun directoryResponse(directory: JsonRawData): AcmeDirectory
    suspend fun newAccountRequest(previousNonce: String): JsonRawData
    suspend fun accountResponse(account: JsonRawData)
    suspend fun newOrderRequest(previousNonce: String): JsonRawData
    suspend fun newOrderResponse(order: JsonRawData): NewAcmeOrder
    suspend fun newAuthzRequest(url: String, previousNonce: String): JsonRawData
    suspend fun authzResponse(authz: JsonRawData): NewAcmeAuthz
    suspend fun createDpopToken(backendNonce: String): DpopToken
    suspend fun newDpopChallengeRequest(accessToken: String, previousNonce: String): JsonRawData
    suspend fun newOidcChallengeRequest(idToken: String, previousNonce: String): JsonRawData
    suspend fun challengeResponse(challenge: JsonRawData)
    suspend fun checkOrderRequest(orderUrl: String, previousNonce: String): JsonRawData
    suspend fun checkOrderResponse(order: JsonRawData): String
    suspend fun finalizeRequest(previousNonce: String): JsonRawData
    suspend fun finalizeResponse(finalize: JsonRawData): String
    suspend fun certificateRequest(previousNonce: String): JsonRawData
}

@Suppress("TooManyFunctions")
@OptIn(ExperimentalUnsignedTypes::class)
class E2EIClientImpl(override val delegate: WireE2eIdentity) : E2EIClient {

    private val defaultDPoPTokenExpiry: UInt = 30U

    override suspend fun directoryResponse(directory: JsonRawData) =
        delegate.directoryResponse(directory.toUByteList()).toAcmeDirectory()

    override suspend fun newAccountRequest(previousNonce: String) =
        delegate.newAccountRequest(previousNonce).toByteArray()

    override suspend fun accountResponse(account: JsonRawData) =
        delegate.newAccountResponse(account.toUByteList())

    override suspend fun newOrderRequest(previousNonce: String) =
        delegate.newOrderRequest(previousNonce).toByteArray()

    override suspend fun newOrderResponse(order: JsonRawData) =
        delegate.newOrderResponse(order.toUByteList()).toNewAcmeOrder()

    override suspend fun newAuthzRequest(url: String, previousNonce: String) =
        delegate.newAuthzRequest(url, previousNonce).toByteArray()

    override suspend fun authzResponse(authz: JsonRawData) =
        delegate.newAuthzResponse(authz.toUByteList()).toNewAcmeAuthz()

    override suspend fun createDpopToken(backendNonce: String) =
        delegate.createDpopToken(expirySecs = defaultDPoPTokenExpiry, backendNonce)

    override suspend fun newDpopChallengeRequest(accessToken: String, previousNonce: String) =
        delegate.newDpopChallengeRequest(accessToken, previousNonce).toByteArray()

    override suspend fun newOidcChallengeRequest(idToken: String, previousNonce: String) =
        delegate.newOidcChallengeRequest(idToken, previousNonce).toByteArray()

    override suspend fun challengeResponse(challenge: JsonRawData) =
        delegate.newChallengeResponse(challenge.toUByteList())

    override suspend fun checkOrderRequest(orderUrl: String, previousNonce: String) =
        delegate.checkOrderRequest(orderUrl, previousNonce).toByteArray()

    override suspend fun checkOrderResponse(order: JsonRawData) =
        delegate.checkOrderResponse(order.toUByteList())

    override suspend fun finalizeRequest(previousNonce: String) =
        delegate.finalizeRequest(previousNonce).toByteArray()

    override suspend fun finalizeResponse(finalize: JsonRawData) =
        delegate.finalizeResponse(finalize.toUByteList())

    override suspend fun certificateRequest(previousNonce: String) =
        delegate.certificateRequest(previousNonce).toByteArray()

    companion object {

        fun ByteArray.toUByteList(): List<UByte> = map { it.toUByte() }
        fun List<UByte>.toByteArray() = toUByteArray().asByteArray()
    }
}
