import { browser, expect } from "@wdio/globals";
import {
    ALICE_ID,
    BOB_ID,
    ccInit,
    CONV_ID,
    createConversation,
    invite,
    newProteusSessionFromMessage,
    newProteusSessionFromPrekey,
    proteusInit,
    roundTripMessage,
    SESSION_ID,
    setup,
    teardown,
} from "./utils.js";
import { afterEach, beforeEach, describe } from "mocha";
import {
    CoreCryptoError,
    CoreCryptoRichError,
    E2eiConversationState,
    GroupInfoEncryptionType,
    RatchetTreeType,
    CoreCryptoContext,
} from "../src/CoreCrypto.js";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("initialization", () => {
    it("should succeed", async () => {
        await ccInit("foo");
    });
});

describe("conversation", () => {
    it("should allow inviting members", async () => {
        await ccInit(ALICE_ID);
        await ccInit(BOB_ID);
        await createConversation(ALICE_ID, CONV_ID);
        const groupInfo = await invite(ALICE_ID, BOB_ID, CONV_ID);
        expect(groupInfo.encryptionType).toBe(
            GroupInfoEncryptionType.Plaintext
        );
        expect(groupInfo.ratchetTreeType).toBe(RatchetTreeType.Full);
    });

    it("should allow sending messages", async () => {
        await ccInit(ALICE_ID);
        await ccInit(BOB_ID);
        await createConversation(ALICE_ID, CONV_ID);
        await invite(ALICE_ID, BOB_ID, CONV_ID);
        const messageText = "Hello world!";
        const [decryptedByAlice, decryptedByBob] = await roundTripMessage(
            ALICE_ID,
            BOB_ID,
            CONV_ID,
            messageText
        );
        expect(decryptedByAlice).toBe(messageText);
        expect(decryptedByBob).toBe(messageText);
    });
});

describe("set_data()", () => {
    it("should persist data to DB", async () => {
        const text = "my message processing checkpoint";

        await ccInit(ALICE_ID);

        const result = await browser.execute(
            async (clientName, text) => {
                const cc = window.ensureCcDefined(clientName);
                const encoder = new TextEncoder();
                const data = encoder.encode(text);
                let dbResultBeforeSet = null;
                await cc.transaction(async (ctx) => {
                    dbResultBeforeSet = await ctx.getData();
                    await ctx.setData(data);
                });
                const dbResultAfterSet = await cc.transaction(async (ctx) => {
                    return await ctx.getData();
                });
                const decoder = new TextDecoder();
                return {
                    beforeSet: dbResultBeforeSet,
                    afterSet: decoder.decode(dbResultAfterSet),
                };
            },
            ALICE_ID,
            text
        );

        expect(result.beforeSet).toBeUndefined();
        expect(result.afterSet).toBe(text);
    });
});

describe("transaction context", () => {
    it("should propagate JS error", async () => {
        const expectedErrorMessage = "Message of expected error";

        await ccInit(ALICE_ID);

        await expect(
            browser.execute(
                async (clientName, expectedMessage) => {
                    const cc = window.ensureCcDefined(clientName);

                    await cc.transaction(async () => {
                        throw new Error(expectedMessage);
                    });
                },
                ALICE_ID,
                expectedErrorMessage
            )
            // wdio wraps the error and prepends the original message with
            // the error type as prefix
        ).rejects.toThrowError(new Error(`Error: ${expectedErrorMessage}`));
    });

    it("should throw error when using invalid context", async () => {
        await ccInit(ALICE_ID);

        const error = await browser.execute(async (clientName) => {
            const cc = window.ensureCcDefined(clientName);

            let context: CoreCryptoContext | null = null;
            await cc.transaction(async (ctx) => {
                context = ctx;
            });

            try {
                await context!.clientKeypackages(
                    window.defaultCipherSuite,
                    window.ccModule.CredentialType.Basic,
                    1
                );
            } catch (err) {
                const error = err as CoreCryptoError;
                return { name: error.name, message: error.message };
            }
            return null;
        }, ALICE_ID);
        expect(error).not.toBeNull();
        expect(error?.name).toEqual("MlsErrorOther");
        expect(error?.message).toEqual(
            "This context has already been finished and can no longer be used."
        );
    });

    it("should roll back transaction after error", async () => {
        await ccInit(ALICE_ID);

        const error = await browser.execute(async (clientName) => {
            const cc = window.ensureCcDefined(clientName);
            const basicCredentialType = window.ccModule.CredentialType.Basic;
            const encoder = new TextEncoder();
            const conversationId = encoder.encode("testConversation");

            const expectedError = new Error("Message of expected error", {
                cause: "This is expected!",
            });
            let thrownError;
            try {
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conversationId,
                        basicCredentialType
                    );
                    throw expectedError;
                });
            } catch (e) {
                thrownError = e;
            }
            if (!(thrownError instanceof Error)) {
                throw new Error("Error wasn't thrown");
            }

            // This would fail with a "Conversation already exists" error, if the above transaction hadn't been rolled back.
            await cc.transaction(async (ctx) => {
                await ctx.createConversation(
                    conversationId,
                    basicCredentialType
                );
            });
            try {
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conversationId,
                        basicCredentialType
                    );
                });
            } catch (err) {
                const error = err as CoreCryptoError;
                return { name: error.name, message: error.message };
            }
            throw new Error("Expected 'Conversation already exists' error");
        }, ALICE_ID);
        expect(error.message).toBe("Conversation already exists");
    });
});

describe("external entropy", () => {
    it("should match with set seed", async () => {
        // Test vectors 1 and 2 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        const vector1 = Uint32Array.from([
            0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd,
            0x1aed8da0, 0xccef36a8, 0xc70d778b, 0x7c5941da, 0x8d485751,
            0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815, 0x69b687c3,
            0x8665eeb2,
        ]);
        const vector2 = Uint32Array.from([
            0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73, 0xa0290fcb,
            0x6965e348, 0x3e53c612, 0xed7aee32, 0x7621b729, 0x434ee69c,
            0xb03371d5, 0xd539d874, 0x281fed31, 0x45fb0a51, 0x1f0ae1ac,
            0x6f4d794b,
        ]);

        await ccInit(ALICE_ID);

        const result = await browser.execute(
            async (clientName, length1, length2) => {
                const cc = window.ensureCcDefined(clientName);
                // Null byte seed
                const seed = new Uint8Array(32);
                await cc.reseedRng(seed);

                const produced1 = await cc.randomBytes(length1);
                const produced2 = await cc.randomBytes(length2);
                return [Array.from(produced1), Array.from(produced2)];
            },
            ALICE_ID,
            vector1.length * vector1.BYTES_PER_ELEMENT,
            vector2.length * vector2.BYTES_PER_ELEMENT
        );

        const resultByteVector1 = new Uint8Array(result[0]);
        const resultByteVector2 = new Uint8Array(result[1]);

        // Use a DataView to solve endianness issues
        const resultVector1 = new Uint32Array(resultByteVector1.buffer);
        const resultVector2 = new Uint32Array(resultByteVector2.buffer);

        expect(resultVector1).toStrictEqual(vector1);
        expect(resultVector2).toStrictEqual(vector2);
    });
});

describe("client identity", () => {
    it("get client public key should work", async () => {
        await ccInit(ALICE_ID);
        const result = await browser.execute(async (clientName) => {
            const cc = window.ensureCcDefined(clientName);
            return (
                await cc.clientPublicKey(
                    window.defaultCipherSuite,
                    window.ccModule.CredentialType.Basic
                )
            ).length;
        }, ALICE_ID);
        expect(result).toBe(32);
    });

    it("requesting client key packages should work", async () => {
        await ccInit(ALICE_ID);
        const result = await browser.execute(async (clientName) => {
            const cc = window.ensureCcDefined(clientName);
            return (
                await cc.transaction(async (ctx) => {
                    return await ctx.clientKeypackages(
                        window.defaultCipherSuite,
                        window.ccModule.CredentialType.Basic,
                        20 // Count of requested key packages
                    );
                })
            ).length;
        }, ALICE_ID);
        expect(result).toBe(20);
    });
});

describe("core crypto errors", () => {
    it("should build correctly", async () => {
        await ccInit(ALICE_ID);
        const result = await browser.execute(async () => {
            const CoreCryptoError = window.ccModule.CoreCryptoError;
            const richErrorJSON: CoreCryptoRichError = {
                error_name: "ErrorTest",
                message: "Hello world",
                error_stack: ["test"],
                proteus_error_code: 22,
            };

            const testStr = JSON.stringify(richErrorJSON);

            const e = new Error(testStr);
            const ccErrMaybe = CoreCryptoError.fromStdError(e);
            const isCorrectInstance = ccErrMaybe instanceof CoreCryptoError;
            const ccErr = ccErrMaybe as CoreCryptoError;
            const ccErr2 = CoreCryptoError.build(e.message);

            return {
                errorNamesAreIdentical:
                    ccErr.name === ccErr2.name && ccErr.name === "ErrorTest",
                proteusErrorCodeIsCorrect: ccErr.proteusErrorCode === 22,
                isCorrectInstance,
            };
        });
        expect(result.errorNamesAreIdentical).toBe(true);
        expect(result.isCorrectInstance).toBe(true);
        expect(result.proteusErrorCodeIsCorrect).toBe(true);
    });
});

describe("proteus", () => {
    it("should initialize correctly", async () => {
        await proteusInit(ALICE_ID);
        const result = await browser.execute(async (clientName) => {
            const lastResortPrekeyId =
                window.ccModule.CoreCrypto.proteusLastResortPrekeyId();
            const cc = window.ensureCcDefined(clientName);
            const [prekey1, prekey2] = await cc.transaction(async (ctx) => {
                const prekey1 = await ctx.proteusLastResortPrekey();
                const prekey2 = await ctx.proteusLastResortPrekey();
                return [prekey1, prekey2];
            });

            return {
                lastResortPrekeyId: lastResortPrekeyId,
                lastResortPrekey1: Array.from(prekey1),
                lastResortPrekey2: Array.from(prekey2),
            };
        }, ALICE_ID);

        const u16MAX = Math.pow(2, 16) - 1;

        expect(result.lastResortPrekeyId).toBe(u16MAX);
        expect(result.lastResortPrekey1).toStrictEqual(
            result.lastResortPrekey2
        );
    });

    it("new session from prekey should succeed", async () => {
        await proteusInit(ALICE_ID);
        await proteusInit(BOB_ID);
        await newProteusSessionFromPrekey(ALICE_ID, BOB_ID, SESSION_ID);
    });

    it("new session from message should succeed", async () => {
        await proteusInit(ALICE_ID);
        await proteusInit(BOB_ID);
        // Session for alice
        await newProteusSessionFromPrekey(ALICE_ID, BOB_ID, SESSION_ID);
        const message = "Hello, world!";
        // Session for bob
        const decryptedMessage = await newProteusSessionFromMessage(
            ALICE_ID,
            BOB_ID,
            SESSION_ID,
            message
        );
        expect(decryptedMessage).toBe(message);
    });

    it("initializing same session twice should fail", async () => {
        await proteusInit(ALICE_ID);
        await proteusInit(BOB_ID);
        // Session for alice
        await newProteusSessionFromPrekey(ALICE_ID, BOB_ID, SESSION_ID);
        const message = "Hello, world!";
        // Session for bob
        const decryptedMessage = await newProteusSessionFromMessage(
            ALICE_ID,
            BOB_ID,
            SESSION_ID,
            message
        );
        expect(decryptedMessage).toBe(message);

        await expect(
            newProteusSessionFromMessage(ALICE_ID, BOB_ID, SESSION_ID, message)
        ).rejects.toThrowError(
            // wdio wraps the error and prepends the original message with
            // the error type as prefix
            new Error(
                "ProteusErrorOther: Another Proteus error occurred but the details are probably irrelevant to clients (101)"
            )
        );
    });
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
                const encoder = new TextEncoder();
                return await cc.transaction(async (ctx) => {
                    return await ctx.e2eiConversationState(
                        encoder.encode(conversationId)
                    );
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
                const identities = await cc.transaction(async (ctx) => {
                    return await ctx.getDeviceIdentities(
                        encoder.encode(conversationId),
                        [encoder.encode(clientName)]
                    );
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
                const encoder = new TextEncoder();
                const identities = await cc.transaction(async (ctx) => {
                    return await ctx.getUserIdentities(
                        encoder.encode(conversationId),
                        ["LcksJb74Tm6N12cDjFy7lQ"]
                    );
                });

                return identities.values().next().value?.pop()?.clientId;
            },
            ALICE_ID,
            CONV_ID
        );
        expect(identities).toBe(ALICE_ID);
    });
});

describe("logger", () => {
    type BrowserLog = {
        level: string;
        message: string;
        source: string;
        timestamp: number;
    };

    it("forwards logs when registered", async () => {
        await ccInit(ALICE_ID);
        const result = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    window.ccModule;

                const logs: string[] = [];
                setLogger({
                    log: (_, json_msg: string) => {
                        logs.push(json_msg);
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Debug);
                const encoder = new TextEncoder();
                const conversationIdBytes = encoder.encode(conversationId);
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conversationIdBytes,
                        window.ccModule.CredentialType.Basic
                    );
                });
                return logs;
            },
            ALICE_ID,
            CONV_ID
        );

        expect(result.length).toBeGreaterThan(0);
    });

    it("can be replaced", async () => {
        await ccInit(ALICE_ID);
        const result = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    window.ccModule;

                const logs: string[] = [];
                setLogger({
                    log: () => {
                        throw Error("Initial logger should not be active");
                    },
                });
                setLogger({
                    log: (_, json_msg: string) => {
                        logs.push(json_msg);
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Debug);
                const encoder = new TextEncoder();
                const conversationIdBytes = encoder.encode(conversationId);
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conversationIdBytes,
                        window.ccModule.CredentialType.Basic
                    );
                });
                return logs;
            },
            ALICE_ID,
            CONV_ID
        );

        expect(result.length).toBeGreaterThan(0);
    });

    it("doesn't forward logs below log level when registered", async () => {
        await ccInit(ALICE_ID);
        const result = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    window.ccModule;

                const logs: string[] = [];
                setLogger({
                    log: (_, json_msg: string) => {
                        logs.push(json_msg);
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Warn);
                const encoder = new TextEncoder();
                const conversationIdBytes = encoder.encode(conversationId);
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conversationIdBytes,
                        window.ccModule.CredentialType.Basic
                    );
                });
                return logs;
            },
            ALICE_ID,
            CONV_ID
        );

        expect(result.length).toBe(0);
    });

    it("when throwing errors they're reported as errors", async () => {
        const expectedErrorMessage = "expected test error in logger test";
        await ccInit(ALICE_ID);
        await browser.execute(
            async (clientName, conversationId, expectedErrorMessage) => {
                const cc = window.ensureCcDefined(clientName);
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    window.ccModule;

                setLogger({
                    log: () => {
                        throw Error(expectedErrorMessage);
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Debug);
                const encoder = new TextEncoder();
                const conversationIdBytes = encoder.encode(conversationId);
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conversationIdBytes,
                        window.ccModule.CredentialType.Basic
                    );
                });
            },
            ALICE_ID,
            CONV_ID,
            expectedErrorMessage
        );

        const logs = (await browser.getLogs("browser")) as BrowserLog[];
        const errorLogs = logs.filter((log) => {
            return log.level === "SEVERE" && log.source === "console-api";
        });

        expect(errorLogs.length).toBeGreaterThan(0);
        expect(errorLogs[0].message).toEqual(
            expect.stringContaining(expectedErrorMessage)
        );
    });

    it("forwards logs with context key/value pairs", async () => {
        await ccInit(ALICE_ID);
        await createConversation(ALICE_ID, CONV_ID);
        await ccInit(BOB_ID);
        await invite(ALICE_ID, BOB_ID, CONV_ID);
        const result = await browser.execute(
            async (aliceName, bobName, conversationId) => {
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    window.ccModule;

                const logs: {
                    level: number;
                    message: string;
                    context: string;
                }[] = [];
                setLogger({
                    log: (level: number, message: string, context: string) => {
                        logs.push({
                            level: level,
                            message: message,
                            context: context,
                        });
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Debug);

                const alice = window.ensureCcDefined(aliceName);
                const bob = window.ensureCcDefined(bobName);
                const encoder = new TextEncoder();
                const messageText = "Hello world!";
                const conversationIdBytes = encoder.encode(conversationId);
                const messageBytes = encoder.encode(messageText);

                const encryptedMessage = await alice.transaction(
                    async (ctx) =>
                        await ctx.encryptMessage(
                            conversationIdBytes,
                            messageBytes
                        )
                );

                await bob.transaction(
                    async (ctx) =>
                        await ctx.decryptMessage(
                            conversationIdBytes,
                            encryptedMessage
                        )
                );

                return logs;
            },
            ALICE_ID,
            BOB_ID,
            CONV_ID
        );

        const proteusErrorLog = result.find(
            (element) => element.message === "Application message"
        )!.context;

        expect(JSON.parse(proteusErrorLog)).toMatchObject({
            group_id: expect.anything(),
            sender_client_id: expect.anything(),
            epoch: expect.anything(),
        });
    });
});

describe("build", () => {
    it("metadata can be retrieved and contain key 'gitDescribe'", async () => {
        await expect(
            browser.execute(async () =>
                window.ccModule.buildMetadata().toJSON()
            )
        ).resolves.toMatchObject({ gitDescribe: expect.anything() });
    });
});

describe("build", () => {
    it("version can be retrieved and is a semantic version number", async () => {
        await expect(
            browser.execute(async () => window.ccModule.version())
        ).resolves.toMatch(
            RegExp(
                // Regex for matching semantic versions from https://semver.org
                "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$"
            )
        );
    });
});

describe("Error type mapping", () => {
    it("should work for conversation already exists", async () => {
        await ccInit(ALICE_ID);
        await createConversation(ALICE_ID, CONV_ID);

        const expectedErrorMessage = "Conversation already exists";

        await expect(
            createConversation(ALICE_ID, CONV_ID)
            // wdio wraps the error and prepends the original message with
            // the error type as prefix
        ).rejects.toThrowError(
            new Error(
                `MlsErrorConversationAlreadyExists: ${expectedErrorMessage}`
            )
        );
    });
});

describe("epoch observer", () => {
    it("should observe new epochs", async () => {
        await ccInit(ALICE_ID);
        const { length, first_id_hex } = await browser.execute(
            async (clientName, conv_id_str) => {
                const conv_id = new TextEncoder().encode(conv_id_str);

                // set up the observer. this just keeps a list of all observations.
                type ObservedEpoch = {
                    conversationId: Uint8Array;
                    epoch: number;
                };
                class Observer {
                    observations: ObservedEpoch[];
                    constructor() {
                        this.observations = [];
                    }
                    async epochChanged(
                        conversationId: Uint8Array,
                        epoch: number
                    ): Promise<void> {
                        this.observations.push({ conversationId, epoch });
                    }
                }
                const observer = new Observer();

                const cc = window.ensureCcDefined(clientName);

                // create the conversation in one transaction
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conv_id,
                        window.ccModule.CredentialType.Basic
                    );
                });

                // register the epoch observer
                await cc.registerEpochObserver(observer);

                // in another transaction, change the epoch
                await cc.transaction(async (ctx) => {
                    await ctx.updateKeyingMaterial(conv_id);
                });

                // we have to explicitly return non-primitives, as anything passed by reference won't make it out of the browser context
                const first_id_hex = Array.from(
                    observer.observations[0].conversationId,
                    (byte) => {
                        return ("0" + (byte & 0xff).toString(16)).slice(-2);
                    }
                ).join("");
                return { length: observer.observations.length, first_id_hex };
            },
            ALICE_ID,
            CONV_ID
        );

        const expect_conversation_id = new TextEncoder().encode(CONV_ID);
        const expect_conversation_id_hex = Array.from(
            expect_conversation_id,
            (byte) => {
                return ("0" + (byte & 0xff).toString(16)).slice(-2);
            }
        ).join("");

        expect(length).toEqual(1);
        expect(first_id_hex).toEqual(expect_conversation_id_hex);
    });
});

describe("database key", () => {
    it("must have correct length", async () => {
        await expect(
            browser.execute(async () => {
                new window.ccModule.DatabaseKey(new Uint8Array(11));
            })
        ).rejects.toThrowError(
            "Error: Invalid database key size, expected 32, got 11"
        );
    });
});
