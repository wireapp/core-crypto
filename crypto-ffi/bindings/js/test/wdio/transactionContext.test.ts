import { browser, expect } from "@wdio/globals";
import { ccInit, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { CoreCryptoContext } from "../../src/CoreCrypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("transaction context", () => {
    it("should propagate JS error", async () => {
        const alice = crypto.randomUUID();
        const expectedErrorMessage = "Message of expected error";

        await ccInit(alice);

        await expect(
            browser.execute(
                async (clientName, expectedMessage) => {
                    const cc = window.ensureCcDefined(clientName);

                    await cc.newTransaction(async () => {
                        throw new Error(expectedMessage);
                    });
                },
                alice,
                expectedErrorMessage
            )
            // wdio wraps the error and prepends the original message with
            // the error type as prefix
        ).rejects.toThrow(new Error(`Error: ${expectedErrorMessage}`));
    });

    it("should throw error when using invalid context", async () => {
        const alice = crypto.randomUUID();
        await ccInit(alice);

        const result = await browser.execute(async (clientName) => {
            const CoreCryptoError = window.ccModule.CoreCryptoError;
            const MlsError = window.ccModule.MlsError;
            const cc = window.ensureCcDefined(clientName);

            let context: CoreCryptoContext | null = null;
            await cc.newTransaction(async (ctx) => {
                context = ctx;
            });

            try {
                await context!.getFilteredCredentials({
                    ciphersuite: window.defaultCipherSuite,
                    credentialType: window.ccModule.CredentialType.Basic,
                });
            } catch (err) {
                const e = err as { context?: { context?: { msg?: string } } };
                return {
                    errorWasThrown: true,
                    isCorrectInstance:
                        CoreCryptoError.Mls.instanceOf(e) &&
                        MlsError.Other.instanceOf(e.inner.mlsError),
                    message:
                        CoreCryptoError.Mls.instanceOf(e) &&
                        MlsError.Other.instanceOf(e.inner.mlsError) &&
                        e.inner.mlsError.inner.msg,
                };
            }
            return {
                errorWasThrown: false,
                isCorrectInstance: false,
                message: false,
            };
        }, alice);
        await expect(result.errorWasThrown).toBe(true);
        await expect(result.isCorrectInstance).toBe(true);
        await expect(result.message).toBe(
            "This transaction context has already been finished and can no longer be used."
        );
    });

    it("should roll back transaction after error", async () => {
        const alice = crypto.randomUUID();
        await ccInit(alice);

        const error = await browser.execute(async (clientName) => {
            const cc = window.ensureCcDefined(clientName);
            const basicCredentialType = window.ccModule.CredentialType.Basic;
            const conversationId = new window.ccModule.ConversationId(
                new TextEncoder().encode("testConversation").buffer
            );
            const CoreCryptoError = window.ccModule.CoreCryptoError;
            const MlsError = window.ccModule.MlsError;

            const expectedError = new Error("Message of expected error", {
                cause: "This is expected!",
            });
            let thrownError;
            try {
                await cc.newTransaction(async (ctx) => {
                    const [credentialRef] = await ctx.getFilteredCredentials({
                        credentialType: basicCredentialType,
                    });
                    await ctx.createConversation(
                        conversationId,
                        credentialRef!
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
            await cc.newTransaction(async (ctx) => {
                const [credentialRef] = await ctx.getFilteredCredentials({
                    credentialType: basicCredentialType,
                });
                await ctx.createConversation(conversationId, credentialRef!);
            });
            try {
                await cc.newTransaction(async (ctx) => {
                    const [credentialRef] = await ctx.getFilteredCredentials({
                        credentialType: basicCredentialType,
                    });
                    await ctx.createConversation(
                        conversationId,
                        credentialRef!
                    );
                });
            } catch (err) {
                if (
                    CoreCryptoError.Mls.instanceOf(err) &&
                    MlsError.ConversationAlreadyExists.instanceOf(
                        err.inner.mlsError
                    )
                ) {
                    return {
                        name: err.inner.mlsError.name,
                        message: err.inner.mlsError.message,
                    };
                }
            }
            throw new Error("Expected 'Conversation already exists' error");
        }, alice);
        await expect(error.message).toBe("MlsError.ConversationAlreadyExists");
    });
});
