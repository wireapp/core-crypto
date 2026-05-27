@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.crypto

import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import testutils.*
import java.util.Base64
import kotlin.test.Test
import kotlin.test.fail

internal class E2EITest {
    companion object {
        private val testCaDer: ByteArray = Base64.getMimeDecoder().decode(
            """
            MIIBrTCCAVOgAwIBAgIUTZQSLl3eOORQ+adTBaACtDinzVIwCgYIKoZIzj0EAwIwIzEhMB8G
            A1UEAwwYQ29yZSBDcnlwdG8gVGVzdCBSb290IENBMCAXDTI2MDUxODExMzcxNFoYDzIxMjYw
            NDI0MTEzNzE0WjAjMSEwHwYDVQQDDBhDb3JlIENyeXB0byBUZXN0IFJvb3QgQ0EwWTATBgcq
            hkjOPQIBBggqhkjOPQMBBwNCAASepKWhYSdxi9vctOj+3iksMZqCYv94ijB7KkHwvaOhsByE
            tzGoCRVuw12fzZ7C5tDChISJDoDuLkMVF17n8IoYo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4G
            A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUcTTkAA9iiyLL9K7ZoQ/KowFwjZ8wHwYDVR0jBBgw
            FoAUcTTkAA9iiyLL9K7ZoQ/KowFwjZ8wCgYIKoZIzj0EAwIDSAAwRQIgGvcMi47MTKh6F4uz
            ppJsiJ+R0Mj4ato4FPg90nm0OtACIQCAIjV4mlXh8Gp2RRSlwuA894+NhyztLPU+vErHy/0I
            uA==
            """.trimIndent()
        )
    }

    @Test
    fun testSetPkiEnvironment() = runTest {
        val hooks = MockPkiEnvironmentHooks()
        val db = newDatabase()
        val pkiEnv = PkiEnvironment.new(hooks, db)

        val cc = CoreCrypto(db)
        cc.setPkiEnvironment(pkiEnv)
        val pkiEnv2 = cc.getPkiEnvironment()
        assert(pkiEnv2 != null)
    }

    @Test
    fun testAddTrustAnchor() = runTest {
        val hooks = MockPkiEnvironmentHooks()
        val db = newDatabase()
        val pkiEnv = PkiEnvironment.new(hooks, db)

        try {
            pkiEnv.addTrustAnchor(testCaDer)
        } catch (exception: Exception) {
            fail("Expected addTrustAnchor not to throw, but it threw: ${exception.message}")
        }
    }

    @Test
    fun testAddIntermediateCert() = runTest {
        val hooks = MockPkiEnvironmentHooks()
        val db = newDatabase()
        val pkiEnv = PkiEnvironment.new(hooks, db)

        try {
            pkiEnv.addIntermediateCert(testCaDer)
        } catch (exception: Exception) {
            fail("Expected addIntermediateCert not to throw, but it threw: ${exception.message}")
        }
    }

    @Test
    fun testInstantiateX509CredentialAcquisition() = runTest {
        val hooks = MockPkiEnvironmentHooks()
        val db = newDatabase()
        val pkiEnv = PkiEnvironment.new(hooks, db)
        val clientId =
            ClientId("LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com".encodeToByteArray())

        val acquisition = X509CredentialAcquisition(
            pkiEnv,
            X509CredentialAcquisitionConfiguration(
                acmeDirectoryUrl = "acme.example.com/directory",
                ciphersuite = CIPHERSUITE_DEFAULT,
                displayName = "Alice Smith",
                clientId = clientId,
                handle = "alice_wire",
                domain = "world.com",
                team = null,
                validityPeriodSecs = 3600uL
            )
        )

        assertThat(acquisition).isNotNull
    }

    @Test
    fun testInstantiateX509CredentialAcquisitionFromCredentialRef() = runTest {
        val db = newDatabase()
        val pkiEnv = PkiEnvironment.new(MockPkiEnvironmentHooks(), db)
        val clientId = ClientId("LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com".encodeToByteArray())
        val config = X509CredentialAcquisitionConfiguration(
            acmeDirectoryUrl = "acme.example.com/directory",
            ciphersuite = CIPHERSUITE_DEFAULT,
            displayName = "Alice Smith",
            clientId = clientId,
            handle = "alice_wire",
            domain = "world.com",
            team = null,
            validityPeriodSecs = 3600uL
        )

        val cc = ccInit(CcInitOptions.WithBasicCredential(clientId = clientId, database = db))
        val credentialRef = cc.findCredentials(clientId = clientId).first()

        val acquisition = X509CredentialAcquisition.newFromCredentialRef(pkiEnv, config, credentialRef)

        assertThat(acquisition).isNotNull
    }

    @Test
    fun conversation_should_be_not_verified_when_at_least_1_of_the_members_uses_a_Basic_credential() =
        runTest {
            val alice = ccInit()
            val bob = ccInit()

            val conversationId = createConversation(bob)
            invite(bob, alice, conversationId)
            assertThat(alice.transaction { ctx -> ctx.e2eiConversationState(conversationId) })
                .isEqualTo(E2eiConversationState.NOT_ENABLED)
            assertThat(bob.transaction { ctx -> ctx.e2eiConversationState(conversationId) })
                .isEqualTo(E2eiConversationState.NOT_ENABLED)
        }

    @Test
    fun e2ei_should_not_be_enabled_for_a_Basic_Credential() = runTest {
        val alice = ccInit()
        assertThat(alice.transaction { ctx -> ctx.e2eiIsEnabled(CIPHERSUITE_DEFAULT) }).isFalse()
    }
}
