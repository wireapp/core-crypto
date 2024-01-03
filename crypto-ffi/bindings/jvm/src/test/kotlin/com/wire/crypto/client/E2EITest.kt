/*
 * Wire
 * Copyright (C) 2023 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 */

package com.wire.crypto.client

import com.wire.crypto.E2eiConversationState
import com.wire.crypto.client.MLSTest.Companion.aliceId
import com.wire.crypto.client.MLSTest.Companion.bobId
import com.wire.crypto.client.MLSTest.Companion.id
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import java.nio.file.Files
import kotlin.test.Test

internal class E2EITest {

    @Test
    fun `sample e2ei enrollment should succeed`() = runTest {
        val root = Files.createTempDirectory("mls").toFile()
        val keyStore = root.resolve("keystore-$aliceId")
        val cc = CoreCryptoCentral(keyStore.absolutePath, "secret")
        val enrollment = cc.e2eiNewEnrollment(
            clientId = "b7ac11a4-8f01-4527-af88-1c30885a7931:6c1866f567616f31@wire.com",
            displayName = "Alice Smith",
            handle = "alice_wire",
            expiryDays = 90u,
            ciphersuite = Ciphersuite.DEFAULT
        )
        val directoryResponse = """{
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order",
            "revokeCert": "https://example.com/acme/revoke-cert"
        }""".trimIndent().toByteArray()
        enrollment.directoryResponse(directoryResponse)

        val previousNonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM"
        enrollment.newAccountRequest(previousNonce)

        val accountResponse = """{
            "status": "valid",
            "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
        }""".trimIndent().toByteArray()
        enrollment.accountResponse(accountResponse)

        enrollment.newOrderRequest(previousNonce)
        val orderResponse = """{
            "status": "pending",
            "expires": "2037-01-05T14:09:07.99Z",
            "notBefore": "2016-01-01T00:00:00Z",
            "notAfter": "2037-01-08T00:00:00Z",
            "identifiers": [
                {
                  "type": "wireapp-id",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://t6wRpI8BRSeviBwwiFp5MQ!6c1866f567616f31@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
                }
            ],
            "authorizations": [
                "https://example.com/acme/authz/PAniVnsZcis"
            ],
            "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
        }""".trimIndent().toByteArray()
        val newOrder = enrollment.newOrderResponse(orderResponse)

        val orderUrl = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth"
        val authzUrl = newOrder.authorizations[0]
        enrollment.newAuthzRequest(authzUrl, previousNonce)
        val authzResponse = """{
            "status": "pending",
            "expires": "2016-01-02T14:09:30Z",
            "identifier": {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://t6wRpI8BRSeviBwwiFp5MQ!6c1866f567616f31@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
            },
            "challenges": [
              {
                "type": "wire-oidc-01",
                "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                "status": "pending",
                "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                "target": "https://dex/dex"
              },
              {
                "type": "wire-dpop-01",
                "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                "status": "pending",
                "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                "target": "https://wire.com/clients/6c1866f567616f31/access-token"
              }
            ]
        }""".toByteArray()
        enrollment.authzResponse(authzResponse)

        val backendNonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU"
        enrollment.createDpopToken(30U, backendNonce)
        val accessToken =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA"
        enrollment.newDpopChallengeRequest(accessToken, previousNonce)
        val dpopChallengeResponse = """{
            "type": "wire-dpop-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "status": "valid",
            "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
        }""".toByteArray()
        enrollment.challengeResponse(dpopChallengeResponse)

        enrollment.checkOrderRequest(orderUrl, previousNonce)
        val checkOrderResponse = """{
          "status": "ready",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://t6wRpI8BRSeviBwwiFp5MQ!6c1866f567616f31@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
            }
          ],
          "authorizations": [
            "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
          ],
          "expires": "2032-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2032-02-09T15:59:20.442908Z"
        }""".toByteArray()
        enrollment.checkOrderResponse(checkOrderResponse)

        enrollment.finalizeRequest(previousNonce)
        val finalizeResponse = """{
          "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
          "status": "valid",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://t6wRpI8BRSeviBwwiFp5MQ!6c1866f567616f31@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
            }
          ],
          "authorizations": [
            "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
          ],
          "expires": "2032-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2032-02-09T15:59:20.442908Z"
        }""".toByteArray()
        enrollment.finalizeResponse(finalizeResponse)

        enrollment.certificateRequest(previousNonce)

        // we cannot go further this `certificateResponse()` validates that the enrollment keypair matches with the
        // certificate public key. So this would require generating the certificate dynamically and would prevent using
        // a static one like in the rest of the test
    }

    @Test
    fun `conversation should be not verified when at least 1 of the members uses a Basic credential`() = runTest {
        val (alice, bob) = newClients(aliceId, bobId)

        bob.createConversation(id)

        val aliceKp = alice.generateKeyPackages(1U, Ciphersuite.DEFAULT, CredentialType.DEFAULT).first()
        val aliceMember = mapOf(aliceId.toClientId() to aliceKp)
        val welcome = bob.addMember(id, aliceMember).welcome!!
        bob.commitAccepted(id)
        val groupId = alice.processWelcomeMessage(welcome)

        assertThat(alice.e2eiConversationState(groupId)).isEqualTo(E2eiConversationState.NOT_ENABLED)
        assertThat(bob.e2eiConversationState(groupId)).isEqualTo(E2eiConversationState.NOT_ENABLED)
    }

    @Test
    fun `e2ei should not be enabled for a Basic Credential`() = runTest {
        val (alice) = newClients(aliceId)
        assertThat(alice.e2eiIsEnabled()).isFalse()
    }
}
