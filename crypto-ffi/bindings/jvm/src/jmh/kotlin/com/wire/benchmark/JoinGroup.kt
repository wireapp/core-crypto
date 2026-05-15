@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.benchmark
import com.wire.crypto.*
import kotlinx.coroutines.runBlocking
import org.openjdk.jmh.annotations.*
import testutils.*
import java.nio.file.Files
import java.util.concurrent.TimeUnit

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Thread)
open class JoinGroup {
    @Param(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519",
        "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
        "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519",
        "MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
        "MLS_256_DHKEMP384_AES256GCM_SHA384_P384"
    )
    var cipherSuite: String = ""

    @Param("1", "10", "100")
    var userCount: Int = 0

    private lateinit var charlieCc: CoreCrypto
    private lateinit var conversationId: ConversationId
    private lateinit var welcome: Welcome

    @Setup(Level.Invocation)
    fun setup() {
        runBlocking {
            val mockTransportProvider = MockMlsTransportSuccessProvider()
            val aliceId = genClientId()
            conversationId = genConversationId()
            val aliceCc = initCc()
            aliceCc.transaction { ctx ->
                ctx.mlsInit(aliceId, mockTransportProvider)
                val credentialRef = ctx.addCredential(Credential.basic(CipherSuite.valueOf(cipherSuite), aliceId))
                ctx.createConversation(conversationId, credentialRef, null)
            }

            val keyPackages = mutableListOf<KeyPackage>()

            if (userCount > 1) {
                repeat(userCount) {
                    val bobId = genClientId()
                    val bobCc = initCc()
                    val kp = bobCc.transaction { ctx ->
                        ctx.mlsInit(bobId, mockTransportProvider)
                        val credentialRef = ctx.addCredential(Credential.basic(CipherSuite.valueOf(cipherSuite), bobId))
                        ctx.generateKeyPackage(credentialRef)
                    }
                    keyPackages.add(kp)
                }
                aliceCc.transaction {
                    it.addClientsToConversation(conversationId, keyPackages)
                }
            }

            val charlieId = genClientId()
            charlieCc = initCc()
            val kp = charlieCc.transaction { ctx ->
                ctx.mlsInit(charlieId, mockTransportProvider)
                val credentialRef = ctx.addCredential(Credential.basic(CipherSuite.valueOf(cipherSuite), charlieId))
                ctx.generateKeyPackage(credentialRef)
            }

            aliceCc.transaction {
                it.addClientsToConversation(conversationId, listOf(kp))
            }
            welcome = mockTransportProvider.getLatestWelcome()
        }
    }

    @Benchmark
    fun bench() = runBlocking {
        charlieCc.transaction { ctx ->
            ctx.processWelcomeMessage(welcome)
        }
    }
}
