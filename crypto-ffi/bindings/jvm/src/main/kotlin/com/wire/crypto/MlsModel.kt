package com.wire.crypto

import com.wire.crypto.uniffi.Ciphersuite as CiphersuiteFfi
import com.wire.crypto.uniffi.Ciphersuites as CiphersuitesFfi

/** Ciphersuites */
@JvmInline
value class Ciphersuites(private val value: Set<Ciphersuite>) {
    companion object {
        /** The default set of ciphersuites. */
        val DEFAULT = Ciphersuites(setOf(Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519))
    }

    internal fun lower() = CiphersuitesFfi(value.map { it.lower() })
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

/** Credential type */
enum class CredentialType {
    /** An application-defined credential. */
    Basic,

    /** A credential based on X509 certificates. */
    X509;

    companion object {
        /** The default credential type. */
        val DEFAULT = Basic
    }

    internal fun lower() =
        when (this) {
            Basic -> com.wire.crypto.uniffi.CredentialType.BASIC
            X509 -> com.wire.crypto.uniffi.CredentialType.X509
        }
}

internal fun com.wire.crypto.uniffi.CredentialType.lift() =
    when (this) {
        com.wire.crypto.uniffi.CredentialType.BASIC -> CredentialType.Basic
        com.wire.crypto.uniffi.CredentialType.X509 -> CredentialType.X509
    }

/** MLS group ID
 * @property value the FFI conversation id
 */
@JvmInline
value class MLSGroupId(val value: com.wire.crypto.uniffi.ConversationId) {
    /** Convert this type wrapper into the FFI version it wraps */
    fun lower() = value
    override fun toString() = value.copyBytes().toHex()
}

/** Construct a group ID */
fun ByteArray.toGroupId() = MLSGroupId(com.wire.crypto.uniffi.ConversationId(this))

/** Construct a group ID */
fun String.toGroupId() = MLSGroupId(com.wire.crypto.uniffi.ConversationId(toByteArray()))

/** Construct a group ID */
fun com.wire.crypto.uniffi.ConversationId.toGroupId() = MLSGroupId(this)

/** Client ID */
@JvmInline
value class ClientId(override val value: ByteArray) : FfiType<ByteArray, com.wire.crypto.uniffi.ClientId> {
    override fun lower() = com.wire.crypto.uniffi.ClientId(value);
}

@OptIn(ExperimentalUnsignedTypes::class)
internal fun com.wire.crypto.uniffi.ClientId.toClientId() = ClientId(asBytes())

/** Construct a client ID */
fun String.toClientId() = ClientId(this.toByteArray())

/** External sender key
 * @property value The FFI external sender key
 */
@JvmInline
value class ExternalSenderKey(val value: com.wire.crypto.uniffi.ExternalSenderKey) {
    /** Convert this type wrapper into the FFI version it wraps */
    fun lower() = value
    override fun toString() = value.copyBytes().toHex()
}

/** Construct an external sender ID */
fun com.wire.crypto.uniffi.ExternalSenderKey.toExternalSenderKey() = ExternalSenderKey(this)

/** Welcome message */
@JvmInline
value class Welcome(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

private fun ByteArray.toWelcome() = Welcome(this)

/** MLS message */
@JvmInline
value class MlsMessage(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

/** Construct an MLS message */
fun ByteArray.toMlsMessage() = MlsMessage(this)

/** Plaintext message */
@JvmInline
value class PlaintextMessage(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

/** Construct a plaintext message */
fun String.toPlaintextMessage() = PlaintextMessage(toByteArray())

/** Signature public key */
@JvmInline
value class SignaturePublicKey(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

internal fun ByteArray.toSignaturePublicKey() = SignaturePublicKey(this)

/** Key package */
@JvmInline
value class MLSKeyPackage(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

internal fun ByteArray.toMLSKeyPackage() = MLSKeyPackage(this)

/** Key package reference */
@JvmInline
value class MLSKeyPackageRef(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

/** Proposal reference */
@JvmInline
value class ProposalRef(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

private fun ByteArray.toProposalRef() = ProposalRef(this)

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
value class GroupInfo(val value: com.wire.crypto.uniffi.GroupInfo) {
    /** Convert this type wrapper into the FFI version which it wraps */
    fun lower(): com.wire.crypto.uniffi.GroupInfo = value
    override fun toString() = value.copyBytes().toHex()
}

private fun com.wire.crypto.uniffi.GroupInfo.toGroupInfo() = GroupInfo(this)

/** The type of group info encryption. */
enum class MlsGroupInfoEncryptionType {
    /** Unencrypted [GroupInfo] */
    PLAINTEXT,

    /** GroupInfo encrypted in a JWE */
    JWE_ENCRYPTED
}

private fun com.wire.crypto.uniffi.MlsGroupInfoEncryptionType.lift() =
    when (this) {
        com.wire.crypto.uniffi.MlsGroupInfoEncryptionType.PLAINTEXT -> MlsGroupInfoEncryptionType.PLAINTEXT
        com.wire.crypto.uniffi.MlsGroupInfoEncryptionType.JWE_ENCRYPTED -> MlsGroupInfoEncryptionType.JWE_ENCRYPTED
    }

/** The ratchet tree type. */
enum class MlsRatchetTreeType {
    /** Plain old and complete `GroupInfo` */
    FULL,

    /**
     * Contains `GroupInfo` changes since previous epoch (not yet implemented)
     * (see [draft](https://github.com/rohan-wire/ietf-drafts/blob/main/mahy-mls-ratchet-tree-delta/draft-mahy-mls-ratchet-tree-delta.md))
     */
    DELTA,

    /** TODO: document this properly */
    BY_REF
}

private fun com.wire.crypto.uniffi.MlsRatchetTreeType.lift() =
    when (this) {
        com.wire.crypto.uniffi.MlsRatchetTreeType.FULL -> com.wire.crypto.MlsRatchetTreeType.FULL
        com.wire.crypto.uniffi.MlsRatchetTreeType.DELTA -> com.wire.crypto.MlsRatchetTreeType.DELTA
        com.wire.crypto.uniffi.MlsRatchetTreeType.BY_REF -> com.wire.crypto.MlsRatchetTreeType.BY_REF
    }

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

private fun com.wire.crypto.uniffi.GroupInfoBundle.lift() =
    GroupInfoBundle(encryptionType.lift(), ratchetTreeType.lift(), payload.toGroupInfo())

/** Data shape for a MLS generic commit + optional bundle (aka stapled commit & welcome) */
data class CommitBundle(
    /** TLS serialized commit wrapped in a MLS message */
    val commit: MlsMessage,
    /** TLS serialized welcome NOT wrapped in a MLS message */
    val welcome: Welcome?,
    /** TLS serialized GroupInfo NOT wrapped in a MLS message */
    val groupInfoBundle: GroupInfoBundle,
    /** New CRL distribution points that appeared by the introduction of a new credential */
    val crlNewDistributionPoints: CrlDistributionPoints?,
)

internal fun com.wire.crypto.uniffi.CommitBundle.lift() =
    CommitBundle(commit.toMlsMessage(), welcome?.toWelcome(), groupInfo.lift(), null)

/** Contains everything client needs to know after decrypting an (encrypted) Welcome message */
data class WelcomeBundle(
    /** MLS Group Id */
    val id: MLSGroupId,
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

internal fun com.wire.crypto.uniffi.WelcomeBundle.lift() =
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

internal fun com.wire.crypto.uniffi.DecryptedMessage.lift() =
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

private fun com.wire.crypto.uniffi.BufferedDecryptedMessage.lift() =
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

internal fun com.wire.crypto.uniffi.WireIdentity.lift() =
    WireIdentity(clientId, status.lift(), thumbprint, credentialType.lift(), x509Identity?.lift())

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

private fun com.wire.crypto.uniffi.X509Identity.lift() =
    X509Identity(
        handle,
        displayName,
        domain,
        certificate,
        serialNumber,
        java.time.Instant.ofEpochSecond(notBefore.toLong()),
        java.time.Instant.ofEpochSecond(notAfter.toLong()),
    )

/**
 * Indicates the standalone status of a device Credential in a MLS group at a moment T. This does
 * not represent the states where a device is not using MLS or is not using end-to-end identity
 */
enum class DeviceStatus {
    /** All is fine */
    Valid,

    /** The Credential's certificate is expired */
    Expired,

    /** The Credential's certificate is revoked (not implemented yet) */
    Revoked,
}

private fun com.wire.crypto.uniffi.DeviceStatus.lift(): DeviceStatus =
    when (this) {
        com.wire.crypto.uniffi.DeviceStatus.VALID -> DeviceStatus.Valid
        com.wire.crypto.uniffi.DeviceStatus.EXPIRED -> DeviceStatus.Expired
        com.wire.crypto.uniffi.DeviceStatus.REVOKED -> DeviceStatus.Revoked
    }

/**
 * Indicates the state of a Conversation regarding end-to-end identity.
 * Note: this does not check pending state (pending commit, pending proposals) so it does not
 * consider members about to be added/removed
 */
enum class E2eiConversationState {
    /** All clients have a valid E2EI certificate */
    Verified,

    /** Some clients are either still Basic or their certificate is expired */
    NotVerified,

    /**
     * All clients are still Basic. If all client have expired certificates,
     * [E2eiConversationState::NotVerified] is returned.
     */
    NotEnabled
}

internal fun com.wire.crypto.uniffi.E2eiConversationState.lift() =
    when (this) {
        com.wire.crypto.uniffi.E2eiConversationState.VERIFIED -> E2eiConversationState.Verified
        com.wire.crypto.uniffi.E2eiConversationState.NOT_VERIFIED -> E2eiConversationState.NotVerified
        com.wire.crypto.uniffi.E2eiConversationState.NOT_ENABLED -> E2eiConversationState.NotEnabled
    }

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
    com.wire.crypto.uniffi.CustomConfiguration(
        keyRotationSpan = keyRotationSpan?.getSeconds().takeIf { it in 0..UInt.MAX_VALUE.toLong() }?.toUInt(),
        wirePolicy = wirePolicy?.lower()
    )

/**
 * Encrypting policy in MLS group
 */
enum class MlsWirePolicy {
    /**
     * Handshake messages are never encrypted
     */
    PLAINTEXT,

    /**
     * Handshake messages are always encrypted
     */
    CIPHERTEXT
}

private fun MlsWirePolicy.lower() =
    when (this) {
        MlsWirePolicy.PLAINTEXT -> com.wire.crypto.uniffi.WirePolicy.PLAINTEXT
        MlsWirePolicy.CIPHERTEXT -> com.wire.crypto.uniffi.WirePolicy.CIPHERTEXT
    }

/** Returned by [MlsTransport] callbacks. */
sealed class MlsTransportResponse {
    /**
     * The message was accepted by the distribution service
     */
    object Success : MlsTransportResponse()

    /**
     * A client should have consumed all incoming messages before re-trying.
     */
    object Retry : MlsTransportResponse()

    /**
     * The message was rejected by the delivery service and there's no recovery.
     * @property reason
     */
    data class Abort(val reason: kotlin.String) : MlsTransportResponse()
}

internal fun MlsTransportResponse.lower() =
    when (this) {
        MlsTransportResponse.Success -> com.wire.crypto.uniffi.MlsTransportResponse.Success
        MlsTransportResponse.Retry -> com.wire.crypto.uniffi.MlsTransportResponse.Retry
        is MlsTransportResponse.Abort -> com.wire.crypto.uniffi.MlsTransportResponse.Abort(reason)
    }

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

internal fun HistorySecret.lower() = com.wire.crypto.uniffi.HistorySecret(clientId.lower(), data)

internal fun com.wire.crypto.uniffi.HistorySecret.lift() =
    HistorySecret(clientId.toClientId(), data)
