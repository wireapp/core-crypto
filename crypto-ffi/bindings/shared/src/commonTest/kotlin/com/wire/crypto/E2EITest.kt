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
        private val testCaPem: String =
            """
            -----BEGIN CERTIFICATE-----
            MIIBkzCCAUWgAwIBAgIUHFYIFRkm33GKIOb4xLeNtkjl3TIwBQYDK2VwMDcxFTAT
            BgNVBAMMDFRlc3QgUm9vdCBDQTERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYT
            AlVTMB4XDTI2MDUyODE1MzA0NFoXDTM2MDUyNTE1MzA0NFowNzEVMBMGA1UEAwwM
            VGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCVVMwKjAF
            BgMrZXADIQDa0nMgIgBZeNM2ysNUVp80zwjZNqPJt7HYK3GX7GPp9aNjMGEwHQYD
            VR0OBBYEFHA0MmaaNGOTuBvdo3zzQoKFJ3p5MB8GA1UdIwQYMBaAFHA0MmaaNGOT
            uBvdo3zzQoKFJ3p5MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAUG
            AytlcANBAJffPzL50OWnmEBo9mGBQfPVzKRIfFc8EaXox1D5VF9cC1r8nRa0hUq+
            LOVS/gxNk618+PKA2bYq67MZQXCYGgk=
            -----END CERTIFICATE-----

            """.trimIndent()
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
            pkiEnv.addTrustAnchor(testCaPem)
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
            pkiEnv.addIntermediateCert(testCaPem)
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
            ClientId("LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com".encodeToByteArray()).parseQualified()

        val acquisition = X509CredentialAcquisition(
            pkiEnv,
            X509CredentialAcquisitionConfiguration(
                acmeDirectoryUrl = "acme.example.com/directory",
                cipherSuite = CIPHERSUITE_DEFAULT,
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
        val qualifiedClientId = ClientId(
            "LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com"
                .encodeToByteArray()
        ).parseQualified()
        val clientId = qualifiedClientId.clientId()
        val config = X509CredentialAcquisitionConfiguration(
            acmeDirectoryUrl = "acme.example.com/directory",
            cipherSuite = CIPHERSUITE_DEFAULT,
            displayName = "Alice Smith",
            clientId = qualifiedClientId,
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
