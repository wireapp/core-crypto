package com.wire.crypto

import Ciphersuite as CiphersuiteFfi

/** Ciphersuites */
@JvmInline
value class Ciphersuites(private val value: Set<Ciphersuite>) {
    companion object {
        /** The default set of ciphersuites. */
        val DEFAULT = Ciphersuites(setOf(Ciphersuite.DEFAULT))
    }

    internal fun lower() = value.map { it.lower() }
}

/** Ciphersuite */
@Suppress("ktlint:standard:enum-entry-name-case")
enum class Ciphersuite {
    /** DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed2551 */
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,

    /** DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P25 */
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256,

    /** DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed2551 */
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,

    /** DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed44 */
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,

    /** DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521 */
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521,

    /** DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448 */
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,

    /** DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384 */
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384;

    companion object {
        /** The default ciphersuite. */
        val DEFAULT = MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    }

    internal fun lower() = when (this) {
        MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 -> CiphersuiteFfi.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519
        MLS_128_DHKEMP256_AES128GCM_SHA256_P256 -> CiphersuiteFfi.MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 -> CiphersuiteFfi.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519
        MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 -> CiphersuiteFfi.MLS_256_DHKEMX448_AES256GCM_SHA512_ED448
        MLS_256_DHKEMP521_AES256GCM_SHA512_P521 -> CiphersuiteFfi.MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 -> CiphersuiteFfi.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448
        MLS_256_DHKEMP384_AES256GCM_SHA384_P384 -> CiphersuiteFfi.MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    }
}

typealias CredentialType = CredentialType

/** Default credential type */
val CREDENTIAL_TYPE_DEFAULT = CredentialType.BASIC

/** Construct a group ID */
fun ByteArray.toGroupId() = ConversationId(this)

/** Construct a group ID */
fun String.toGroupId() = ConversationId(toByteArray())

/** Construct a group ID */
fun ConversationId.toGroupId() = this

/** Convert a group id to a string */
fun ConversationId.toString() = copyBytes().toHex()

/** Client ID */
@JvmInline
value class ClientId(override val value: ByteArray) : FfiType<ByteArray, ClientId> {
    override fun lower() = ClientId(value)
}

@OptIn(ExperimentalUnsignedTypes::class)
internal fun ClientId.toClientId() = ClientId(copyBytes())

/** Construct a client ID */
fun String.toClientId() = ClientId(this.toByteArray())

/** External sender key
 * @property value The FFI external sender key
 */
@JvmInline
value class ExternalSenderKey(val value: ExternalSenderKey) {
    /** Convert this type wrapper into the FFI version it wraps */
    fun lower() = value

    /** Copy the bytes from the external sender key */
    fun copyBytes() = value.copyBytes()

    override fun toString() = value.copyBytes().toHex()
}

/** Construct an external sender ID */
fun ByteArray.toExternalSenderKey() = ExternalSenderKey(com.wire.crypto.uniffi.ExternalSenderKey(this))

/** Welcome message
 * @property value the FFI welcome message
 */
@JvmInline
value class Welcome(val value: Welcome) {
    /** Convert this type wrapper into the FFI version it wraps */
    fun lower() = value

    /** Copy the bytes from the Welcome */
    fun copyBytes() = value.copyBytes()

    override fun toString() = value.copyBytes().toHex()
}

/** Construct a Welcome */
fun ByteArray.toWelcome() = Welcome(this)

private fun Welcome.toWelcome() = Welcome(this)

/** Key package
 * @property value the internal wrapped FFI type
 */
@JvmInline
value class MLSKeyPackage(val value: KeyPackage) {
    /** Lower this wrapper to the internal FFI type */
    fun lower(): KeyPackage = value

    override fun toString() = value.copyBytes().toHex()
}

/** Construct a KeyPackage from bytes */
fun ByteArray.toMLSKeyPackage() = MLSKeyPackage(this)

internal fun KeyPackage.toMLSKeyPackage() = MLSKeyPackage(this)

/** AVS secret
 * @property value the FFI secret key
 */
@JvmInline
value class AvsSecret(val value: com.wire.crypto.uniffi.SecretKey) {
    /** Lower this wrapper to the internal wrapped FFI type */
    fun lower() = value

    /** Copy the bytes from the Secret */
    fun copyBytes() = value.copyBytes()

    override fun toString() = value.copyBytes().toHex()
}

/** Construct an AVS secret */
fun ByteArray.toAvsSecret() = AvsSecret(com.wire.crypto.uniffi.SecretKey(this))

internal fun com.wire.crypto.uniffi.SecretKey.toAvsSecret() = AvsSecret(this)

/** ExternallyGeneratedHandle */
@JvmInline
value class ExternallyGeneratedHandle(override val value: List<ByteArray>) :
    FfiType<List<ByteArray>, List<ByteArray>> {
    override fun lower(): List<ByteArray> = value

    override fun toString() = value.joinToString("") { it.toString() }
}

internal fun List<ByteArray>.toExternallyGeneratedHandle() = ExternallyGeneratedHandle(map { it })

/** CRL distribution points */
@JvmInline
value class CrlDistributionPoints(override val value: Set<java.net.URI>) :
    FfiType<Set<java.net.URI>, List<String>> {
    override fun lower(): List<String> = value.asSequence().map { it.toString() }.toList()

    override fun toString() = value.joinToString(", ") { it.toString() }
}

internal fun List<String>.toCrlDistributionPoint() =
    CrlDistributionPoints(asSequence().map { java.net.URI(it) }.toSet())

/** Group info
 * @property value The FFI external group info
 */
@JvmInline
value class GroupInfo(val value: GroupInfo) {
    /** Convert this type wrapper into the FFI version which it wraps */
    fun lower(): GroupInfo = value

    /** Copy the bytes from the group info */
    fun copyBytes() = value.copyBytes()

    override fun toString() = value.copyBytes().toHex()
}

/** Construct a GroupInfo from bytes */
fun ByteArray.toGroupInfo() = GroupInfo(this)

private fun GroupInfo.toGroupInfo() = GroupInfo(this)

typealias MlsGroupInfoEncryptionType = MlsGroupInfoEncryptionType
typealias MlsRatchetTreeType = MlsRatchetTreeType

/**
 * @property encryptionType see [GroupInfoEncryptionType]
 * @property ratchetTreeType see [MlsRatchetTreeType]
 * @property payload see [GroupInfo]
 */
data class GroupInfoBundle(
    val encryptionType: MlsGroupInfoEncryptionType,
    val ratchetTreeType: MlsRatchetTreeType,
    val payload: GroupInfo,
)

private fun GroupInfoBundle.lift() =
    GroupInfoBundle(encryptionType, ratchetTreeType, payload.toGroupInfo())

/** Data shape for a MLS generic commit + optional bundle (aka stapled commit & welcome) */
data class CommitBundle(
    /** TLS serialized commit wrapped in a MLS message */
    val commit: ByteArray,
    /** TLS serialized welcome NOT wrapped in a MLS message */
    val welcome: Welcome?,
    /** TLS serialized GroupInfo NOT wrapped in a MLS message */
    val groupInfoBundle: GroupInfoBundle,
    /** New CRL distribution points that appeared by the introduction of a new credential */
    val crlNewDistributionPoints: CrlDistributionPoints?,
)

internal fun CommitBundle.lift() =
    CommitBundle(commit, welcome?.toWelcome(), groupInfo.lift(), null)

/** Contains everything client needs to know after decrypting an (encrypted) Welcome message */
data class WelcomeBundle(
    /** MLS Group Id */
    val id: ConversationId,
    /** New CRL distribution points that appeared by the introduction of a new credential */
    val crlNewDistributionPoints: CrlDistributionPoints?,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as WelcomeBundle

        if (id != other.id) return false
        if (crlNewDistributionPoints != other.crlNewDistributionPoints) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + (crlNewDistributionPoints?.hashCode() ?: 0)
        return result
    }
}

internal fun WelcomeBundle.lift() =
    WelcomeBundle(id.toGroupId(), crlNewDistributionPoints?.toCrlDistributionPoint())

/**
 * Represents the potential items a consumer might require after passing us an encrypted message we
 * have decrypted for him
 */
data class DecryptedMessage(
    /** Decrypted text message */
    val message: ByteArray?,
    /**
     * Is the conversation still active after receiving this commit aka has the user been removed
     * from the group
     */
    val isActive: Boolean,
    /** Delay time in seconds to feed caller timer for committing */
    val commitDelay: Long?,
    /**
     * [ClientId] of the sender of the message being decrypted. Only present for application
     * messages.
     */
    val senderClientId: ClientId?,
    /** Is the epoch changed after decrypting this message */
    val hasEpochChanged: Boolean,
    /**
     * Identity claims present in the sender credential Only present when the credential is a x509
     * certificate Present for all messages
     */
    val identity: WireIdentity,
    /**
     * Identity claims present in the sender credential Only present when the credential is a x509
     * certificate Present for all messages
     */
    val bufferedMessages: List<BufferedDecryptedMessage>?,
    /** New CRL distribution points that appeared by the introduction of a new credential */
    val crlNewDistributionPoints: CrlDistributionPoints?,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DecryptedMessage

        if (message != null) {
            if (other.message == null) return false
            if (!message.contentEquals(other.message)) return false
        } else if (other.message != null) {
            return false
        }
        if (isActive != other.isActive) return false
        if (commitDelay != other.commitDelay) return false
        if (senderClientId != other.senderClientId) return false
        if (hasEpochChanged != other.hasEpochChanged) return false
        if (identity != other.identity) return false
        if (crlNewDistributionPoints != other.crlNewDistributionPoints) return false

        return true
    }

    override fun hashCode(): Int {
        var result = message?.contentHashCode() ?: 0
        result = 31 * result + isActive.hashCode()
        result = 31 * result + (commitDelay?.hashCode() ?: 0)
        result = 31 * result + (senderClientId?.hashCode() ?: 0)
        result = 31 * result + hasEpochChanged.hashCode()
        result = 31 * result + identity.hashCode()
        result = 31 * result + (crlNewDistributionPoints?.hashCode() ?: 0)
        return result
    }
}

internal fun DecryptedMessage.lift() =
    DecryptedMessage(
        message,
        isActive,
        commitDelay?.toLong(),
        senderClientId?.toClientId(),
        hasEpochChanged,
        identity.lift(),
        bufferedMessages?.map { it.lift() },
        crlNewDistributionPoints?.toCrlDistributionPoint(),
    )

/** Type safe recursion of [DecryptedMessage] */
data class BufferedDecryptedMessage(
    /** @see DecryptedMessage.message */
    val message: ByteArray?,
    /** @see DecryptedMessage.isActive */
    val isActive: Boolean,
    /** @see DecryptedMessage.commitDelay */
    val commitDelay: Long?,
    /** @see DecryptedMessage.senderClientId */
    val senderClientId: ClientId?,
    /** @see DecryptedMessage.hasEpochChanged */
    val hasEpochChanged: Boolean,
    /** @see DecryptedMessage.identity */
    val identity: WireIdentity,
    /** @see DecryptedMessage.crlNewDistributionPoints */
    val crlNewDistributionPoints: CrlDistributionPoints?,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DecryptedMessage

        if (message != null) {
            if (other.message == null) return false
            if (!message.contentEquals(other.message)) return false
        } else if (other.message != null) {
            return false
        }
        if (isActive != other.isActive) return false
        if (commitDelay != other.commitDelay) return false
        if (senderClientId != other.senderClientId) return false
        if (hasEpochChanged != other.hasEpochChanged) return false
        if (identity != other.identity) return false
        if (crlNewDistributionPoints != other.crlNewDistributionPoints) return false

        return true
    }

    override fun hashCode(): Int {
        var result = message?.contentHashCode() ?: 0
        result = 31 * result + isActive.hashCode()
        result = 31 * result + (commitDelay?.hashCode() ?: 0)
        result = 31 * result + (senderClientId?.hashCode() ?: 0)
        result = 31 * result + hasEpochChanged.hashCode()
        result = 31 * result + identity.hashCode()
        result = 31 * result + (crlNewDistributionPoints?.hashCode() ?: 0)
        return result
    }
}

private fun BufferedDecryptedMessage.lift() =
    BufferedDecryptedMessage(
        message,
        isActive,
        commitDelay?.toLong(),
        senderClientId?.toClientId(),
        hasEpochChanged,
        identity.lift(),
        crlNewDistributionPoints?.toCrlDistributionPoint(),
    )

/** Represents a client using Wire's end-to-end identity solution */
data class WireIdentity(
    /** Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov` */
    val clientId: String,
    /** Status of the Credential at the moment T when this object is created */
    val status: DeviceStatus,
    /** MLS thumbprint */
    val thumbprint: String,
    /** Indicates whether the credential is Basic or X509 */
    val credentialType: CredentialType,
    /** In case [credentialType] is [CredentialType.X509] this is populated */
    val x509Identity: X509Identity?,
)

internal fun WireIdentity.lift() =
    WireIdentity(clientId, status, thumbprint, credentialType, x509Identity?.lift())

/**
 * Represents the parts of WireIdentity that are specific to a X509 certificate (and not a Basic
 * one).
 */
data class X509Identity(
    /** user handle e.g. `john_wire` */
    val handle: String,
    /** Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy` */
    val displayName: String,
    /** DNS domain for which this identity proof was generated e.g. `whitehouse.gov` */
    val domain: String,
    /** X509 certificate identifying this client in the MLS group ; PEM encoded */
    val certificate: String,
    /** X509 certificate serial number */
    val serialNumber: String,
    /** X509 certificate not before as Unix timestamp */
    val notBefore: java.time.Instant,
    /** X509 certificate not after as Unix timestamp */
    val notAfter: java.time.Instant,
)

private fun X509Identity.lift() =
    X509Identity(
        handle,
        displayName,
        domain,
        certificate,
        serialNumber,
        java.time.Instant.ofEpochSecond(notBefore.toLong()),
        java.time.Instant.ofEpochSecond(notAfter.toLong()),
    )

typealias DeviceStatus = DeviceStatus
typealias E2eiConversationState = E2eiConversationState

/**
 * Configuration of MLS group
 * @property keyRotationSpan Duration in seconds after which we will automatically force a self-update commit.
 *                           Note: This isn't currently implemented.
 * @property wirePolicy Defines if handshake messages are encrypted or not.
 *                      Note: encrypted handshake messages are not supported by wire-server.
 */
data class CustomConfiguration(
    var keyRotationSpan: java.time.Duration?,
    var wirePolicy: MlsWirePolicy?
)

internal fun CustomConfiguration.lower() =
    CustomConfiguration(
        keyRotationSpan = keyRotationSpan?.getSeconds().takeIf { it in 0..UInt.MAX_VALUE.toLong() }?.toUInt(),
        wirePolicy = wirePolicy
    )

typealias MlsWirePolicy = WirePolicy
typealias MlsTransportResponse = MlsTransportResponse

/**
 * An entity / data which has been packaged by the application to be encrypted and transmitted in an application message.
 */
@JvmInline
value class MlsTransportData(override val value: ByteArray) : Uniffi

/**
 * You must implement this interface and pass the implementing object to [CoreCrypto.provideTransport].
 * CoreCrypto uses it to communicate with the delivery service.
 */
interface MlsTransport {
    /**
     * Send a message to the delivery service.
     */
    suspend fun sendMessage(mlsMessage: ByteArray): MlsTransportResponse

    /**
     * Send a commit bundle to the delivery service.
     */
    suspend fun sendCommitBundle(commitBundle: CommitBundle): MlsTransportResponse

    /**
     * Prepare a history secret before being sent
     */
    suspend fun prepareForTransport(historySecret: HistorySecret): MlsTransportData
}

/**
 * A `HistorySecret` encodes sufficient client state that it can be used to instantiate an
 */
data class HistorySecret(
    /**
     * Client id of the associated history client
     */
    val clientId: ClientId,
    /**
     * Secrets for the associated history client
     */
    val data: ByteArray
)

internal fun HistorySecret.lower() = HistorySecret(clientId.lower(), data)

internal fun HistorySecret.lift() =
    HistorySecret(clientId.toClientId(), data)
