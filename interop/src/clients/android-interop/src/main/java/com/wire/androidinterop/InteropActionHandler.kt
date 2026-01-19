package com.wire.androidinterop

import com.wire.crypto.ClientId
import com.wire.crypto.CommitBundle
import com.wire.crypto.ConversationId
import com.wire.crypto.CoreCrypto
import com.wire.crypto.DatabaseKey
import com.wire.crypto.HistorySecret
import com.wire.crypto.Keypackage
import com.wire.crypto.MlsTransport
import com.wire.crypto.MlsTransportData
import com.wire.crypto.MlsTransportResponse
import com.wire.crypto.Welcome
import com.wire.crypto.ciphersuiteFromU16
import com.wire.crypto.credentialBasic
import com.wire.crypto.openDatabase
import java.nio.file.Files
import java.security.SecureRandom
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random

class DummyTransport : MlsTransport {
    override suspend fun sendCommitBundle(commitBundle: CommitBundle): MlsTransportResponse {
        return MlsTransportResponse.Success
    }

    override suspend fun sendMessage(mlsMessage: ByteArray): MlsTransportResponse {
        return MlsTransportResponse.Success
    }

    override suspend fun prepareForTransport(historySecret: HistorySecret): MlsTransportData {
        return historySecret.data
    }
}

class InteropActionHandler(val coreCrypto: CoreCrypto) {
    @OptIn(ExperimentalEncodingApi::class)
    suspend fun handleAction(action: InteropAction): Result<String> {
        return when (action) {
            is InteropAction.MLS.InitMLS -> {
                coreCrypto.transaction({ context ->
                    context.mlsInit(
                        clientId = ClientId(action.clientId),
                        transport = DummyTransport()
                    )

                    context.addCredential(
                        credentialBasic(
                            clientId = ClientId(action.clientId),
                            ciphersuite = ciphersuiteFromU16(action.ciphersuite.toUShort())
                        )
                    )
                })

                return Result.success("MLS initialized")
            }

            is InteropAction.MLS.AddClient -> {
                coreCrypto.transaction { context ->
                    context.addClientsToConversation(
                        ConversationId(action.conversationId),
                        keyPackages = listOf(
                            Keypackage(action.keyPackage)
                        )
                    )
                }

                return Result.success("Client added")
            }

            is InteropAction.MLS.RemoveClient -> {
                coreCrypto.transaction { context ->
                    context.removeClientsFromConversation(ConversationId(action.conversationId), listOf(ClientId(action.clientId)))
                }

                return Result.success("Client removed")
            }

            is InteropAction.MLS.DecryptMessage -> {
                coreCrypto.transaction { context ->
                    context.decryptMessage(ConversationId(bytes = action.conversationId), action.message)
                }.message?.let {
                    return Result.success(Base64.Default.encode(it))
                }
                Result.success("decrypted protocol message")
            }

            is InteropAction.MLS.EncryptMessage -> {
                coreCrypto.transaction { context ->
                    context.encryptMessage(ConversationId(action.conversationId), action.message)
                }.let {
                    Result.success(Base64.Default.encode(it))
                }
            }

            is InteropAction.MLS.GetKeyPackage -> {
                coreCrypto.transaction { context ->
                    val credential = context.findCredentials(
                        ciphersuite = ciphersuiteFromU16(action.ciphersuite.toUShort()),
                        clientId = null,
                        publicKey = null,
                        credentialType = null,
                        earliestValidity = null
                    ).first()
                    context.generateKeypackage(credential, null)
                }.let {
                    Result.success(Base64.Default.encode(it.serialize()))
                }
            }

            is InteropAction.MLS.ProcessWelcome -> {
                coreCrypto.transaction { context ->
                    context.processWelcomeMessage(Welcome(action.welcome))
                }.let {
                    Result.success(Base64.Default.encode(it.id.copyBytes()))
                }
            }

            is InteropAction.Proteus.InitProteus -> {
                coreCrypto.transaction({ context ->
                    context.proteusInit()
                })

                return Result.success("Proteus initialized")
            }

            is InteropAction.Proteus.GetPrekey -> {
                coreCrypto.transaction({ context ->
                    context.proteusNewPrekey(action.id)
                }).let {
                    Result.success(Base64.Default.encode(it))
                }
            }

            is InteropAction.Proteus.SessionFromPrekey -> {
                coreCrypto.transaction { context ->
                    context.proteusSessionFromPrekey(
                        sessionId = action.sessionId,
                        prekey = action.prekey
                    )
                }
                Result.success("Session created")
            }

            is InteropAction.Proteus.SessionFromMessage -> {
                coreCrypto.transaction { context ->
                    context.proteusSessionFromMessage(
                        sessionId = action.sessionId,
                        envelope = action.message
                    )
                }.let {
                    Result.success(Base64.Default.encode(it))
                }
            }

            is InteropAction.Proteus.EncryptProteusMessage -> {
                coreCrypto.transaction({ context ->
                    context.proteusEncrypt(
                        sessionId = action.sessionId,
                        plaintext = action.message
                    )
                }).let {
                    Result.success(Base64.Default.encode(it))
                }
            }

            is InteropAction.Proteus.DecryptProteusMessage -> {
                coreCrypto.transaction { context ->
                    context.proteusDecrypt(
                        sessionId = action.sessionId,
                        ciphertext = action.message
                    )
                }.let {
                    Result.success(Base64.Default.encode(it))
                }
            }

            is InteropAction.Proteus.GetProteusFingerprint -> {
                coreCrypto.transaction { context ->
                    context.proteusFingerprint()
                }.let {
                    Result.success(it)
                }
            }
        }
    }

    companion object {
        private fun genDatabaseKey(): DatabaseKey {
            val bytes = ByteArray(32)
            val random = SecureRandom()
            random.nextBytes(bytes)
            return DatabaseKey(bytes)
        }

        private fun randomIdentifier(n: Int = 12): String {
            val charPool: List<Char> = ('a'..'z') + ('A'..'Z') + ('0'..'9')
            return (1..n)
                .map { Random.nextInt(0, charPool.size).let { charPool[it] } }
                .joinToString("")
        }

        suspend fun defaultCoreCryptoClient(): CoreCrypto {
            val root = Files.createTempDirectory("mls").toFile()
            val path = root.resolve("keystore-${randomIdentifier()}")
            val database = openDatabase(path.absolutePath, key = genDatabaseKey())

            return CoreCrypto(database)
        }
    }
}
