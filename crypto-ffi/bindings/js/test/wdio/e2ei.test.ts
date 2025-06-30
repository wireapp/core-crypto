import { browser, expect } from "@wdio/globals";
import {
    ALICE_ID,
    ccInit,
    CONV_ID,
    createConversation,
    setup,
    teardown,
} from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { E2eiConversationState } from "../../src/CoreCrypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("end to end identity", () => {
    it("enrollment flow should succeed", async () => {
        await ccInit(ALICE_ID);
        await browser.execute(async (clientName) => {
            const cc = window.ensureCcDefined(clientName);
            const ciphersuite = window.defaultCipherSuite;
            const encoder = new TextEncoder();
            const jsonToByteArray = (json: object) =>
                encoder.encode(JSON.stringify(json, null, 0));
            const clientId =
                "b7ac11a4-8f01-4527-af88-1c30885a7931:4959bc6ab12f2846@wire.com";
            const displayName = "Alice Smith";
            const handle = "alice_wire";
            const expirySec = 90 * 24 * 3600;

            await cc.transaction(async (ctx) => {
                let enrollment = await ctx.e2eiNewEnrollment(
                    clientId,
                    displayName,
                    handle,
                    expirySec,
                    ciphersuite
                );

                const directoryResp = {
                    newNonce: "https://example.com/acme/new-nonce",
                    newAccount: "https://example.com/acme/new-account",
                    newOrder: "https://example.com/acme/new-order",
                    revokeCert: "https://example.com/acme/revoke-cert",
                };
                await enrollment.directoryResponse(
                    jsonToByteArray(directoryResp)
                );

                const previousNonce =
                    "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM";
                await enrollment.newAccountRequest(previousNonce);

                const accountResp = {
                    status: "valid",
                    orders: "https://example.com/acme/acct/evOfKhNU60wg/orders",
                };
                await enrollment.newAccountResponse(
                    jsonToByteArray(accountResp)
                );

                await enrollment.newOrderRequest(previousNonce);

                const newOrderResp = {
                    status: "pending",
                    expires: "2037-01-05T14:09:07.99Z",
                    notBefore: "2016-01-01T00:00:00Z",
                    notAfter: "2037-01-08T00:00:00Z",
                    identifiers: [
                        {
                            type: "wireapp-user",
                            value: '{"name":"Alice Smith","domain":"wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                        },
                        {
                            type: "wireapp-device",
                            value: '{"name":"Alice Smith","domain":"wire.com","client-id":"wireapp://t6wRpI8BRSeviBwwiFp5MQ!4959bc6ab12f2846@wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                        },
                    ],
                    authorizations: [
                        "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
                        "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz",
                    ],
                    finalize:
                        "https://example.com/acme/order/TOlocE8rfgo/finalize",
                };
                await enrollment.newOrderResponse(
                    jsonToByteArray(newOrderResp)
                );

                const userAuthzUrl =
                    "https://example.com/acme/wire-acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL";
                await enrollment.newAuthzRequest(userAuthzUrl, previousNonce);

                const userAuthzResp = {
                    status: "pending",
                    expires: "2037-01-02T14:09:30Z",
                    identifier: {
                        type: "wireapp-user",
                        value: '{"name":"Alice Smith","domain":"wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                    },
                    challenges: [
                        {
                            type: "wire-oidc-01",
                            url: "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                            status: "pending",
                            token: "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                            target: "https://dex/dex",
                        },
                    ],
                };
                await enrollment.newAuthzResponse(
                    jsonToByteArray(userAuthzResp)
                );

                const deviceAuthzUrl =
                    "https://example.com/acme/wire-acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz";
                await enrollment.newAuthzRequest(deviceAuthzUrl, previousNonce);

                const deviceAuthzResp = {
                    status: "pending",
                    expires: "2037-01-02T14:09:30Z",
                    identifier: {
                        type: "wireapp-device",
                        value: '{"name":"Alice Smith","domain":"wire.com","client-id":"wireapp://t6wRpI8BRSeviBwwiFp5MQ!4959bc6ab12f2846@wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                    },
                    challenges: [
                        {
                            type: "wire-dpop-01",
                            url: "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                            status: "pending",
                            token: "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                            target: "https://wire.com/clients/4959bc6ab12f2846/access-token",
                        },
                    ],
                };
                await enrollment.newAuthzResponse(
                    jsonToByteArray(deviceAuthzResp)
                );

                const backendNonce =
                    "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";
                const dpopTokenExpirySecs = 3600;
                await enrollment.createDpopToken(
                    dpopTokenExpirySecs,
                    backendNonce
                );

                const accessToken =
                    "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InlldjZPWlVudWlwbmZrMHRWZFlLRnM5MWpSdjVoVmF6a2llTEhBTmN1UEUifX0.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY4MzczNzc1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsImp0aSI6Ijk4NGM1OTA0LWZhM2UtNDVhZi1iZGM1LTlhODMzNjkxOGUyYiIsIm5vbmNlIjoiYjNWSU9YTk9aVE4xVUV0b2FXSk9VM1owZFVWdWJFMDNZV1ZIUVdOb2NFMCIsImNoYWwiOiJTWTc0dEptQUlJaGR6UnRKdnB4Mzg5ZjZFS0hiWHV4USIsImNuZiI6eyJraWQiOiJocG9RV2xNUmtjUURKN2xNcDhaSHp4WVBNVDBJM0Vhc2VqUHZhWmlGUGpjIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZVVGM1QxVmZTMXBpYUV0SFIxUjRaMGQ0WTJsa1VVZHFiMUpXWkdOdFlWQmpSblI0VG5Gd1gydzJTU0o5ZlEuZXlKcFlYUWlPakUyTnpVNU5qRTNOVFlzSW1WNGNDSTZNVFkzTmpBME9ERTFOaXdpYm1KbUlqb3hOamMxT1RZeE56VTJMQ0p6ZFdJaU9pSnBiWEJ3T25kcGNtVmhjSEE5VGtSRmVWcEhXWGRPYW1NeVRYcEdhMDVFUW1sT1ZHeHNXVzFXYlUxcVVYbGFWRWw2VGxSak5FNVhVUzgyTldNellXTXhZVEUyTXpGak1UTTJRR1Y0WVcxd2JHVXVZMjl0SWl3aWFuUnBJam9pTlRBM09HWmtaVEl0TlRCaU9DMDBabVZtTFdJeE5EQXRNekJrWVRrellqQmtZems1SWl3aWJtOXVZMlVpT2lKaU0xWkpUMWhPVDFwVVRqRlZSWFJ2WVZkS1QxVXpXakJrVlZaMVlrVXdNMWxYVmtoUlYwNXZZMFV3SWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5c2IyTmhiR2h2YzNRNk5Ua3pNRGN2SWl3aVkyaGhiQ0k2SWxOWk56UjBTbTFCU1Vsb1pIcFNkRXAyY0hnek9EbG1Oa1ZMU0dKWWRYaFJJbjAuQk1MS1Y1OG43c1dITXkxMlUtTHlMc0ZJSkd0TVNKcXVoUkZvYnV6ZTlGNEpBN1NjdlFWSEdUTFF2ZVZfUXBfUTROZThyeU9GcEphUTc1VW5ORHR1RFEiLCJjbGllbnRfaWQiOiJpbXBwOndpcmVhcHA9TkRFeVpHWXdOamMyTXpGa05EQmlOVGxsWW1WbU1qUXlaVEl6TlRjNE5XUS82NWMzYWMxYTE2MzFjMTM2QGV4YW1wbGUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Tf10dkKrNikGNgGhIdkrMHb0v6Jpde09MaIyBeuY6KORcxuglMGY7_V9Kd0LcVVPMDy1q4xbd39ZqosGz1NUBQ";
                await enrollment.newDpopChallengeRequest(
                    accessToken,
                    previousNonce
                );
                const dpopChallengeResp = {
                    type: "wire-dpop-01",
                    url: "https://example.com/acme/chall/prV_B7yEyA4",
                    status: "valid",
                    token: "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0",
                    target: "http://example.com/target",
                };
                await enrollment.newDpopChallengeResponse(
                    jsonToByteArray(dpopChallengeResp)
                );

                // simulate the OAuth redirect
                const storeHandle = await ctx.e2eiEnrollmentStash(enrollment);
                enrollment = await ctx.e2eiEnrollmentStashPop(storeHandle);

                const idToken =
                    "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ";
                await enrollment.newOidcChallengeRequest(
                    idToken,
                    previousNonce
                );

                const oidcChallengeResp = {
                    type: "wire-oidc-01",
                    url: "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
                    status: "valid",
                    token: "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb",
                    target: "http://example.com/target",
                };
                await enrollment.newOidcChallengeResponse(
                    jsonToByteArray(oidcChallengeResp)
                );

                const orderUrl =
                    "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";
                await enrollment.checkOrderRequest(orderUrl, previousNonce);

                const checkOrderResp = {
                    status: "ready",
                    finalize:
                        "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
                    identifiers: [
                        {
                            type: "wireapp-user",
                            value: '{"name":"Alice Smith","domain":"wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                        },
                        {
                            type: "wireapp-device",
                            value: '{"name":"Alice Smith","domain":"wire.com","client-id":"wireapp://t6wRpI8BRSeviBwwiFp5MQ!4959bc6ab12f2846@wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                        },
                    ],
                    authorizations: [
                        "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
                        "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz",
                    ],
                    expires: "2032-02-10T14:59:20Z",
                    notBefore: "2013-02-09T14:59:20.442908Z",
                    notAfter: "2032-02-09T15:59:20.442908Z",
                };
                await enrollment.checkOrderResponse(
                    jsonToByteArray(checkOrderResp)
                );

                await enrollment.finalizeRequest(previousNonce);
                const finalizeResp = {
                    certificate:
                        "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
                    status: "valid",
                    finalize:
                        "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
                    identifiers: [
                        {
                            type: "wireapp-user",
                            value: '{"name":"Alice Smith","domain":"wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                        },
                        {
                            type: "wireapp-device",
                            value: '{"name":"Alice Smith","domain":"wire.com","client-id":"wireapp://t6wRpI8BRSeviBwwiFp5MQ!4959bc6ab12f2846@wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                        },
                    ],
                    authorizations: [
                        "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
                        "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz",
                    ],
                    expires: "2032-02-10T14:59:20Z",
                    notBefore: "2013-02-09T14:59:20.442908Z",
                    notAfter: "2032-02-09T15:59:20.442908Z",
                };
                await enrollment.finalizeResponse(
                    jsonToByteArray(finalizeResp)
                );

                await enrollment.certificateRequest(previousNonce);
            });
        }, ALICE_ID);
    });

    it("should not be enabled on conversation with basic credential", async () => {
        await ccInit(ALICE_ID);
        await createConversation(ALICE_ID, CONV_ID);
        const conversationState = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const cid = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conversationId)
                );
                return await cc.transaction(async (ctx) => {
                    return await ctx.e2eiConversationState(cid);
                });
            },
            ALICE_ID,
            CONV_ID
        );
        expect(conversationState).toBe(E2eiConversationState.NotEnabled);
    });

    it("identities can be queried by client id", async () => {
        await ccInit(ALICE_ID);
        await createConversation(ALICE_ID, CONV_ID);
        const identities = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const encoder = new TextEncoder();
                const cid = new window.ccModule.ConversationId(
                    encoder.encode(conversationId)
                );
                const identities = await cc.transaction(async (ctx) => {
                    return await ctx.getDeviceIdentities(cid, [
                        new window.ccModule.ClientId(
                            encoder.encode(clientName)
                        ),
                    ]);
                });

                return identities.pop()?.clientId;
            },
            ALICE_ID,
            CONV_ID
        );
        expect(identities).toBe(ALICE_ID);
    });

    it("identities can be queried by user id", async () => {
        const ALICE_ID = "LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com";
        await ccInit(ALICE_ID);
        await createConversation(ALICE_ID, CONV_ID);
        const identities = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const cid = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conversationId)
                );
                const identities = await cc.transaction(async (ctx) => {
                    return await ctx.getUserIdentities(cid, [
                        "LcksJb74Tm6N12cDjFy7lQ",
                    ]);
                });

                return identities.values().next().value?.pop()?.clientId;
            },
            ALICE_ID,
            CONV_ID
        );
        expect(identities).toBe(ALICE_ID);
    });
});
