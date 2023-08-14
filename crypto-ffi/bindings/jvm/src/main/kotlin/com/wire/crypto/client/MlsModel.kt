package com.wire.crypto.client

import com.wire.crypto.MlsGroupInfoEncryptionType
import com.wire.crypto.MlsRatchetTreeType

@JvmInline
value class Ciphersuites(private val value: Set<Ciphersuite>) {
    companion object {

        val DEFAULT = Ciphersuites(setOf(Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519))
    }

    fun lower() = value.map { it.lower() }
}

enum class Ciphersuite {
    // DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,

    // DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256,

    // DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,

    // DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,

    // DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521,

    // DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,

    // DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384,

    // x25519Kyber768Draft00 Hybrid KEM | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_X25519KYBER768DRAFT00_AES128GCM_SHA256_Ed25519;

    companion object {

        val DEFAULT = MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    }

    fun lower() = (ordinal + 1).toUShort()
}

enum class CredentialType {
    Basic,
    X509;

    companion object {
        val DEFAULT = Basic
    }

    fun lower() = when (this) {
        Basic -> com.wire.crypto.MlsCredentialType.BASIC
        X509 -> com.wire.crypto.MlsCredentialType.X509
    }
}

@JvmInline
value class MLSGroupId(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

fun ByteArray.toGroupId() = MLSGroupId(this)
fun String.toGroupId() = MLSGroupId(toByteArray())

@JvmInline
value class ClientId(override val value: String) : FfiType<String, com.wire.crypto.ClientId> {

    override fun lower() = value.toByteArray()
}

@OptIn(ExperimentalUnsignedTypes::class)
fun com.wire.crypto.ClientId.toClientId() = ClientId(String(toUByteArray().asByteArray()))
fun String.toClientId() = ClientId(this)

@JvmInline
value class ExternalSenderKey(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

@JvmInline
value class Welcome(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

fun ByteArray.toWelcome() = Welcome(this)

@JvmInline
value class MlsMessage(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

fun ByteArray.toMlsMessage() = MlsMessage(this)

@JvmInline
value class AvsSecret(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

fun ByteArray.toAvsSecret() = AvsSecret(this)

@JvmInline
value class PlaintextMessage(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

fun String.toPlaintextMessage() = PlaintextMessage(toByteArray())

@JvmInline
value class SignaturePublicKey(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

fun ByteArray.toSignaturePublicKey() = SignaturePublicKey(this)

@JvmInline
value class MLSKeyPackage(override val value: ByteArray) : Uniffi {
    // FIXME: inconsistent representation across FFI ; ByteArray in out position, List<UByte> in in position
    fun lowerUByte() = value.toUByteList()
    override fun toString() = value.toHex()
}

fun ByteArray.toMLSKeyPackage() = MLSKeyPackage(this)

@JvmInline
value class MLSKeyPackageRef(override val value: ByteArray) : Uniffi {
    // FIXME: inconsistent representation across FFI ; ByteArray in out position, List<UByte> in in position
    fun lowerUByte() = value.toUByteList()
    override fun toString() = value.toHex()
}

@JvmInline
value class ProposalRef(override val value: ByteArray) : Uniffi {
    // FIXME: inconsistent representation across FFI ; ByteArray in out position, List<UByte> in in position
    fun lowerUByte() = value.toUByteList()
    override fun toString() = value.toHex()
}

fun ByteArray.toProposalRef() = ProposalRef(this)

@JvmInline
value class ExternallyGeneratedHandle(override val value: List<ByteArray>) :
    FfiType<List<ByteArray>, List<ByteArray>> {
    override fun lower(): List<ByteArray> = value

    override fun toString() = value.joinToString("") { it.toString() }
}

fun List<ByteArray>.toExternallyGeneratedHandle() = ExternallyGeneratedHandle(map { it })

@JvmInline
value class GroupInfo(override val value: ByteArray) : Uniffi {
    override fun toString() = value.toHex()
}

fun ByteArray.toGroupInfo() = GroupInfo(this)

data class GroupInfoBundle(
    val encryptionType: MlsGroupInfoEncryptionType,
    val ratchetTreeType: MlsRatchetTreeType,
    val payload: GroupInfo,
)

fun com.wire.crypto.GroupInfoBundle.lift() =
    GroupInfoBundle(encryptionType, ratchetTreeType, payload.toGroupInfo())

data class CommitBundle(
    val commit: MlsMessage,
    val welcome: Welcome?,
    val groupInfoBundle: GroupInfoBundle,
)

fun com.wire.crypto.CommitBundle.lift() =
    CommitBundle(commit.toMlsMessage(), welcome?.toWelcome(), groupInfo.lift())

fun com.wire.crypto.ConversationInitBundle.lift() =
    CommitBundle(commit.toMlsMessage(), null, groupInfo.lift())

fun com.wire.crypto.MemberAddedMessages.lift() =
    CommitBundle(commit.toMlsMessage(), welcome.toWelcome(), groupInfo.lift())

/**
 * Returned when a Proposal is created. Helps roll backing a local proposal
 */
data class ProposalBundle(
    /**
     * The proposal message to send to the DS
     */
    val proposal: MlsMessage,
    /**
     * A unique identifier of the proposal to rollback it later if required with [MlsClient.clearPendingProposal]
     */
    val proposalRef: ProposalRef
)

fun com.wire.crypto.ProposalBundle.lift() =
    ProposalBundle(proposal.toMlsMessage(), proposalRef.toProposalRef())

/**
 * Represents the potential items a consumer might require after passing us an encrypted message we have decrypted for him
 */
data class DecryptedMessage(
    /**
     * Decrypted text message
     */
    val message: ByteArray?,
    /**
     * Only when decrypted message is a commit, CoreCrypto will renew local proposal which could not make it in the commit.
     * This will contain either:
     *   - local pending proposal not in the accepted commit
     *   - If there is a pending commit, its proposals which are not in the accepted commit
     */
    val proposals: Set<ProposalBundle>,
    /**
     * Is the conversation still active after receiving this commit aka has the user been removed from the group
     */
    val isActive: Boolean,
    /**
     * Delay time in seconds to feed caller timer for committing
     */
    val commitDelay: Long?,
    /**
     * [ClientId] of the sender of the message being decrypted. Only present for application messages.
     */
    val senderClientId: ClientId?,
    /**
     * Is the epoch changed after decrypting this message
     */
    val hasEpochChanged: Boolean,
    /**
     * Identity claims present in the sender credential
     * Only present when the credential is a x509 certificate
     * Present for all messages
     */
    val identity: WireIdentity?,
    /**
     * Identity claims present in the sender credential
     * Only present when the credential is a x509 certificate
     * Present for all messages
     */
    val bufferedMessages: List<BufferedDecryptedMessage>?,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DecryptedMessage

        if (message != null) {
            if (other.message == null) return false
            if (!message.contentEquals(other.message)) return false
        } else if (other.message != null) return false
        if (proposals != other.proposals) return false
        if (isActive != other.isActive) return false
        if (commitDelay != other.commitDelay) return false
        if (senderClientId != other.senderClientId) return false
        if (hasEpochChanged != other.hasEpochChanged) return false
        if (identity != other.identity) return false

        return true
    }

    override fun hashCode(): Int {
        var result = message?.contentHashCode() ?: 0
        result = 31 * result + proposals.hashCode()
        result = 31 * result + isActive.hashCode()
        result = 31 * result + (commitDelay?.hashCode() ?: 0)
        result = 31 * result + (senderClientId?.hashCode() ?: 0)
        result = 31 * result + hasEpochChanged.hashCode()
        result = 31 * result + (identity?.hashCode() ?: 0)
        return result
    }
}

fun com.wire.crypto.DecryptedMessage.lift() = DecryptedMessage(
    message,
    proposals.asSequence().map { it.lift() }.toSet(),
    isActive,
    commitDelay?.toLong(),
    senderClientId?.toClientId(),
    hasEpochChanged,
    identity?.lift(),
    bufferedMessages?.map { it.lift() }
)

/**
 * Type safe recursion of [DecryptedMessage]
 */
data class BufferedDecryptedMessage(
    /** @see DecryptedMessage.message */
    val message: ByteArray?,
    /** @see DecryptedMessage.proposals */
    val proposals: Set<ProposalBundle>,
    /** @see DecryptedMessage.isActive */
    val isActive: Boolean,
    /** @see DecryptedMessage.commitDelay */
    val commitDelay: Long?,
    /** @see DecryptedMessage.senderClientId */
    val senderClientId: ClientId?,
    /** @see DecryptedMessage.hasEpochChanged */
    val hasEpochChanged: Boolean,
    /** @see DecryptedMessage.identity */
    val identity: WireIdentity?,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DecryptedMessage

        if (message != null) {
            if (other.message == null) return false
            if (!message.contentEquals(other.message)) return false
        } else if (other.message != null) return false
        if (proposals != other.proposals) return false
        if (isActive != other.isActive) return false
        if (commitDelay != other.commitDelay) return false
        if (senderClientId != other.senderClientId) return false
        if (hasEpochChanged != other.hasEpochChanged) return false
        if (identity != other.identity) return false

        return true
    }

    override fun hashCode(): Int {
        var result = message?.contentHashCode() ?: 0
        result = 31 * result + proposals.hashCode()
        result = 31 * result + isActive.hashCode()
        result = 31 * result + (commitDelay?.hashCode() ?: 0)
        result = 31 * result + (senderClientId?.hashCode() ?: 0)
        result = 31 * result + hasEpochChanged.hashCode()
        result = 31 * result + (identity?.hashCode() ?: 0)
        return result
    }
}

fun com.wire.crypto.BufferedDecryptedMessage.lift() = BufferedDecryptedMessage(
    message,
    proposals.asSequence().map { it.lift() }.toSet(),
    isActive,
    commitDelay?.toLong(),
    senderClientId?.toClientId(),
    hasEpochChanged,
    identity?.lift()
)

/**
 * Represents a client using Wire's end-to-end identity solution
 */
data class WireIdentity(
    /**
     * Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov`
     */
    val clientId: String,
    /**
     * user handle e.g. `john_wire`
     */
    val handle: String,
    /**
     * Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
     */
    val displayName: String,
    /**
     * DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
     */
    val domain: String
)

fun com.wire.crypto.WireIdentity.lift() = WireIdentity(clientId, handle, displayName, domain)
