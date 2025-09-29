import { browser, expect } from "@wdio/globals";
import { ccInit, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import {
    CoreCryptoError,
    CoreCryptoContext,
    ErrorType,
} from "../../src/CoreCrypto";

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

                    await cc.transaction(async () => {
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
                const error = err as CoreCryptoError<ErrorType>;
                return { name: error.name, message: error.message };
            }
            return null;
        }, alice);
        expect(error).not.toBeNull();
        expect(error?.name).toEqual("MlsErrorOther");
        expect(error?.message).toEqual(
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
                new TextEncoder().encode("testConversation")
            );

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
                const error = err as CoreCryptoError<ErrorType>;
                return { name: error.name, message: error.message };
            }
            throw new Error("Expected 'Conversation already exists' error");
        }, alice);
        expect(error.message).toBe("Conversation already exists");
    });
});
