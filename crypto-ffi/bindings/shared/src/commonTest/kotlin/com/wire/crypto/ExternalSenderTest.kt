@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.crypto

import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import testutils.*
import kotlin.test.*

class ExternalSenderTest : HasMockDeliveryService() {
    companion object {
        private val id: ConversationId = genConversationId()

        // A real Ed25519 public key, encoded as a JWK. Hardcoded because
        // `KeyPairGenerator.getInstance("Ed25519")` is unavailable on Android < API 33.
        private val FIXTURE_JWK =
            """{"kty":"OKP","crv":"Ed25519","x":"SN_PbU3M_gqC4ztSO0uagUZVabiXU1KVdRJF1ciRnnM"}""".toByteArray()
    }

    @BeforeTest
    fun setup() {
        setupMocks()
    }

    @Test
    fun parseJwk_produces_a_sender_usable_in_createConversation() = runTest {
        val externalSender = ExternalSender.parseJwk(FIXTURE_JWK)
        val (alice) = newClients(genClientId())

        val retrievedKey = alice.transaction { ctx ->
            val credentials = ctx.findCredentials(
                clientId = null,
                publicKey = null,
                ciphersuite = CIPHERSUITE_DEFAULT,
                credentialType = CREDENTIAL_TYPE_DEFAULT,
                earliestValidity = null,
            )
            ctx.createConversation(id, credentials.last(), externalSender)
            ctx.getExternalSender(id)
        }

        assertThat(retrievedKey.copyBytes()).isEqualTo(externalSender.serialize())
    }

    @Test
    fun parsePublicKey_accepts_the_bytes_produced_by_serialize() {
        val fromJwk = ExternalSender.parseJwk(FIXTURE_JWK)
        val fromBytes = ExternalSender.parsePublicKey(fromJwk.serialize(), SignatureScheme.ED25519)
        assertThat(fromJwk).isEqualTo(fromBytes)
    }

    @Test
    fun parseJwk_rejects_malformed_bytes() {
        assertFailsWith<CoreCryptoException> {
            ExternalSender.parseJwk(byteArrayOf(0, 1, 2, 3))
        }
    }
}
