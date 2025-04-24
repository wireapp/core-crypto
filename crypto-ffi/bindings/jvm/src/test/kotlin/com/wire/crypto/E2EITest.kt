package com.wire.crypto

import com.wire.crypto.MLSTest.Companion.ALICE_ID
import com.wire.crypto.MLSTest.Companion.BOB_ID
import com.wire.crypto.MLSTest.Companion.id
import com.wire.crypto.testutils.genDatabaseKey
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import java.nio.file.Files
import kotlin.test.BeforeTest
import kotlin.test.Test

internal class E2EITest {
    @BeforeTest
    fun setup() {
        MLSTest.mockDeliveryService = MockMlsTransportSuccessProvider()
    }

    @Test
    fun sample_e2ei_enrollment_should_succeed() = runTest {
        val root = Files.createTempDirectory("mls").toFile()
        val keyStore = root.resolve("keystore-$ALICE_ID")
        val key = genDatabaseKey()
        val cc = CoreCrypto(keyStore.absolutePath, key)
        val enrollment = cc.transaction {
            it.e2eiNewEnrollment(
                clientId = "b7ac11a4-8f01-4527-af88-1c30885a7931:6c1866f567616f31@wire.com",
                displayName = "Alice Smith",
                handle = "alice_wire",
                expirySec = (90 * 24 * 3600).toUInt(),
                ciphersuite = Ciphersuite.DEFAULT
            )
        }
        val directoryResponse = """{
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order",
            "revokeCert": "https://example.com/acme/revoke-cert"
        }"""
            .trimIndent()
            .toByteArray()
        enrollment.directoryResponse(directoryResponse)

        val previousNonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM"
        enrollment.newAccountRequest(previousNonce)

        val accountResponse =
            """{
            "status": "valid",
            "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
        }"""
                .trimIndent()
                .toByteArray()
        enrollment.accountResponse(accountResponse)

        enrollment.newOrderRequest(previousNonce)
        val orderResponse =
            """{
            "status": "pending",
            "expires": "2037-01-05T14:09:07.99Z",
            "notBefore": "2016-01-01T00:00:00Z",
            "notAfter": "2037-01-08T00:00:00Z",
            "identifiers": [
                {
                  "type": "wireapp-user",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
                },
                {
                  "type": "wireapp-device",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://t6wRpI8BRSeviBwwiFp5MQ!6c1866f567616f31@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
                }
            ],
            "authorizations": [
              "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
              "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
            ],
            "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
        }"""
                .trimIndent()
                .toByteArray()
        val newOrder = enrollment.newOrderResponse(orderResponse)

        val orderUrl = "https://example.com/acme/wire-acme/order/6SDQFoXfk1UT75qRfzurqxWCMEatapiL"

        val userAuthzUrl = newOrder.authorizations[0]
        enrollment.newAuthzRequest(userAuthzUrl, previousNonce)
        val userAuthzResponse =
            """{
            "status": "pending",
            "expires": "2037-01-02T14:09:30Z",
            "identifier": {
              "type": "wireapp-user",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
            },
            "challenges": [
              {
                "type": "wire-oidc-01",
                "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                "status": "pending",
                "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                "target": "http://example.com/target"
              }
            ]
        }"""
                .toByteArray()
        enrollment.authzResponse(userAuthzResponse)

        val deviceAuthzUrl = newOrder.authorizations[0]
        enrollment.newAuthzRequest(deviceAuthzUrl, previousNonce)
        val deviceAuthzResponse =
            """{
            "status": "pending",
            "expires": "2037-01-02T14:09:30Z",
            "identifier": {
              "type": "wireapp-device",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://t6wRpI8BRSeviBwwiFp5MQ!6c1866f567616f31@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
            },
            "challenges": [
              {
                "type": "wire-dpop-01",
                "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                "status": "pending",
                "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                "target": "https://wire.com/clients/6c1866f567616f31/access-token"
              }
            ]
        }"""
                .toByteArray()
        enrollment.authzResponse(deviceAuthzResponse)

        val backendNonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU"
        enrollment.createDpopToken(30U, backendNonce)
        val accessToken =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA"
        enrollment.newDpopChallengeRequest(accessToken, previousNonce)
        val dpopChallengeResponse =
            """{
            "type": "wire-dpop-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "status": "valid",
            "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0",
            "target": "http://example.com/target"
        }"""
                .toByteArray()
        enrollment.dpopChallengeResponse(dpopChallengeResponse)

        enrollment.checkOrderRequest(orderUrl, previousNonce)
        val checkOrderResponse =
            """{
          "status": "ready",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-user",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
            },
            {
              "type": "wireapp-device",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://t6wRpI8BRSeviBwwiFp5MQ!6c1866f567616f31@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
            }
          ],
          "authorizations": [
            "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
            "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
          ],
          "expires": "2032-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2032-02-09T15:59:20.442908Z"
        }"""
                .toByteArray()
        enrollment.checkOrderResponse(checkOrderResponse)

        enrollment.finalizeRequest(previousNonce)
        val finalizeResponse =
            """{
          "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
          "status": "valid",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-user",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
            },
            {
              "type": "wireapp-device",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://t6wRpI8BRSeviBwwiFp5MQ!6c1866f567616f31@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
            }
          ],
          "authorizations": [
            "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
            "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
          ],
          "expires": "2032-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2032-02-09T15:59:20.442908Z"
        }"""
                .toByteArray()
        enrollment.finalizeResponse(finalizeResponse)

        enrollment.certificateRequest(previousNonce)

        // we cannot go further this `certificateResponse()` validates that the enrollment keypair
        // matches with the
        // certificate public key. So this would require generating the certificate dynamically and
        // would prevent using
        // a static one like in the rest of the test
    }

    @Test
    fun conversation_should_be_not_verified_when_at_least_1_of_the_members_uses_a_Basic_credential() =
        runTest {
            val (alice, bob) = newClients(ALICE_ID, BOB_ID)

            bob.transaction { it.createConversation(id) }

            val aliceKp = alice.transaction { it.generateKeyPackages(1U, Ciphersuite.DEFAULT, CredentialType.DEFAULT).first() }
            bob.transaction { it.addMember(id, listOf(aliceKp)) }
            val welcome = MLSTest.mockDeliveryService.getLatestWelcome()
            val groupId = alice.transaction { it.processWelcomeMessage(welcome).id }

            assertThat(alice.transaction { it.e2eiConversationState(groupId) }).isEqualTo(E2eiConversationState.NotEnabled)
            assertThat(bob.transaction { it.e2eiConversationState(groupId) }).isEqualTo(E2eiConversationState.NotEnabled)
        }

    @Test
    fun e2ei_should_not_be_enabled_for_a_Basic_Credential() = runTest {
        val (alice) = newClients(ALICE_ID)
        assertThat(alice.transaction { it.e2eiIsEnabled() }).isFalse()
    }
}
