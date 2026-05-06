import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { CoreCryptoContext } from "@wireapp/core-crypto/browser";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("transaction context", () => {
    it("should propagate JS error", async () => {
        const expectedErrorMessage = "Message of expected error";
        await expect(
            browser.execute(async (expectedMessage) => {
                const cc = await window.helpers.ccInit();
                await cc.transaction(async () => {
                    throw new Error(expectedMessage);
                });
            }, expectedErrorMessage)
            // wdio wraps the error and prepends the original message with
            // the error type as prefix
        ).rejects.toThrow(new Error(`Error: ${expectedErrorMessage}`));
    });

    it("should throw error when using invalid context", async () => {
        const result = await browser.execute(async () => {
            const CoreCryptoError = window.ccModule.CoreCryptoError;
            const MlsError = window.ccModule.MlsError;
            const cc = await window.helpers.ccInit();

            let context: CoreCryptoContext | null = null;
            await cc.transaction(async (ctx) => {
                context = ctx;
            });

            try {
                await context!.findCredentials({
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
        });
        await expect(result.errorWasThrown).toBe(true);
        await expect(result.isCorrectInstance).toBe(true);
        await expect(result.message).toBe(
            "This transaction context has already been finished and can no longer be used."
        );
    });

    it("should roll back transaction after error", async () => {
        const error = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            const basicCredentialType = window.ccModule.CredentialType.Basic;
            const conversationId = new window.ccModule.ConversationId(
                new TextEncoder().encode("testConversation")
            );
            const CoreCryptoError = window.ccModule.CoreCryptoError;
            const MlsError = window.ccModule.MlsError;

            const expectedError = new Error("Message of expected error", {
                cause: "This is expected!",
            });
            let thrownError;
            try {
                await cc.transaction(async (ctx) => {
                    const [credentialRef] = await ctx.findCredentials({
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

            // This would throw a "Conversation already exists" error, if the above transaction hadn't been rolled back.
            await cc.transaction(async (ctx) => {
                const [credentialRef] = await ctx.findCredentials({
                    credentialType: basicCredentialType,
                });
                await ctx.createConversation(conversationId, credentialRef!);
            });
            try {
                await cc.transaction(async (ctx) => {
                    const [credentialRef] = await ctx.findCredentials({
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
        });
        await expect(error.message).toBe("MlsError.ConversationAlreadyExists");
    });
});
