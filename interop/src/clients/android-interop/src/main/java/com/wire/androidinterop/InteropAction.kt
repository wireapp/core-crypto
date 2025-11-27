package com.wire.androidinterop

import android.content.Intent
import kotlinx.serialization.Serializable
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@Serializable
sealed class InteropAction {
    sealed class MLS : InteropAction() {
        class InitMLS(val clientId: ByteArray, val ciphersuite: Int) : MLS()

        class GetKeyPackage(val ciphersuite: Int) : MLS()

        class AddClient(val conversationId: ByteArray, val keyPackage: ByteArray) : MLS()

        class RemoveClient(val conversationId: ByteArray, val clientId: ByteArray) : MLS()

        class ProcessWelcome(val welcome: ByteArray) : MLS()

        class EncryptMessage(val conversationId: ByteArray, val message: ByteArray) : MLS()

        class DecryptMessage(val conversationId: ByteArray, val message: ByteArray) : MLS()
    }

    sealed class Proteus : InteropAction() {
        class InitProteus : Proteus()

        class GetPrekey(val id: UShort) : Proteus()

        class SessionFromPrekey(val sessionId: String, val prekey: ByteArray) : Proteus()

        class SessionFromMessage(val sessionId: String, val message: ByteArray) : Proteus()

        class EncryptProteusMessage(val sessionId: String, val message: ByteArray) : Proteus()

        class DecryptProteusMessage(val sessionId: String, val message: ByteArray) : Proteus()

        class GetProteusFingerprint() : Proteus()
    }

    companion object {
        @OptIn(ExperimentalEncodingApi::class)
        fun fromIntent(intent: Intent): InteropAction {
            return when (intent.getStringExtra("action")) {
                "init-mls" -> {
                    val clientId = intent.getStringExtra("client_id") ?: throw IllegalArgumentException("client_id is missing")
                    val ciphersuite = intent.getIntExtra("ciphersuite", 0)

                    MLS.InitMLS(clientId = Base64.Default.decode(clientId), ciphersuite = ciphersuite)
                }

                "get-key-package" -> {
                    val ciphersuite = intent.getIntExtra("ciphersuite", 0)
                    MLS.GetKeyPackage(ciphersuite = ciphersuite)
                }

                "add-client" -> {
                    val conversationId = intent.getStringExtra("cid") ?: throw IllegalArgumentException("conversation_id is missing")
                    val keyPackage = intent.getStringExtra("kp") ?: throw IllegalArgumentException("key_package is missing")

                    MLS.AddClient(conversationId = Base64.Default.decode(conversationId), keyPackage = Base64.Default.decode(keyPackage))
                }

                "remove-client" -> {
                    val conversationId = intent.getStringExtra("cid") ?: throw IllegalArgumentException("conversation_id is missing")
                    val clientId = intent.getStringExtra("client_id") ?: throw IllegalArgumentException("client_id is missing")

                    MLS.RemoveClient(conversationId = Base64.Default.decode(conversationId), clientId = Base64.Default.decode(clientId))
                }

                "process-welcome" -> {
                    val welcome = intent.getStringExtra("welcome") ?: throw IllegalArgumentException("welcome is missing")

                    MLS.ProcessWelcome(Base64.Default.decode(welcome))
                }

                "encrypt-message" -> {
                    val conversationId = intent.getStringExtra("cid") ?: throw IllegalArgumentException("conversation_id is missing")
                    val message = intent.getStringExtra("message") ?: throw IllegalArgumentException("message is missing")

                    MLS.EncryptMessage(Base64.Default.decode(conversationId), Base64.Default.decode(message))
                }

                "decrypt-message" -> {
                    val conversationId = intent.getStringExtra("cid") ?: throw IllegalArgumentException("conversation_id is missing")
                    val message = intent.getStringExtra("message") ?: throw IllegalArgumentException("message is missing")

                    MLS.DecryptMessage(Base64.Default.decode(conversationId), Base64.Default.decode(message))
                }

                "init-proteus" -> {
                    Proteus.InitProteus()
                }

                "get-prekey" -> {
                    val id = intent.getIntExtra("id", 0).toUShort()
                    Proteus.GetPrekey(id)
                }

                "session-from-prekey" -> {
                    val sessionId = intent.getStringExtra("session_id") ?: throw IllegalArgumentException("session_id is missing")
                    val prekey = intent.getStringExtra("prekey") ?: throw IllegalArgumentException("prekey is missing")

                    Proteus.SessionFromPrekey(sessionId = sessionId, prekey = Base64.Default.decode(prekey))
                }

                "session-from-message" -> {
                    val sessionId = intent.getStringExtra("session_id") ?: throw IllegalArgumentException("session_id is missing")
                    val message = intent.getStringExtra("message") ?: throw IllegalArgumentException("message is missing")

                    Proteus.SessionFromMessage(sessionId = sessionId, message = Base64.Default.decode(message))
                }

                "encrypt-proteus" -> {
                    val sessionId = intent.getStringExtra("session_id") ?: throw IllegalArgumentException("session_id is missing")
                    val message = intent.getStringExtra("message") ?: throw IllegalArgumentException("message is missing")

                    Proteus.EncryptProteusMessage(sessionId = sessionId, message = Base64.Default.decode(message))
                }

                "decrypt-proteus" -> {
                    val sessionId = intent.getStringExtra("session_id") ?: throw IllegalArgumentException("session_id is missing")
                    val message = intent.getStringExtra("message") ?: throw IllegalArgumentException("message is missing")

                    Proteus.DecryptProteusMessage(sessionId = sessionId, message = Base64.Default.decode(message))
                }

                "get-fingerprint" -> {
                    Proteus.GetProteusFingerprint()
                }

                else -> {
                    throw IllegalArgumentException("Unknown action: ${intent.getStringExtra("action")}")
                }
            }
        }
    }
}
