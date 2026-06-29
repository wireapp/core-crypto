import { runOnPlatform, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { CoreCryptoContext } from "#core-crypto";
import { expect } from "chai";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("transaction context", () => {
    it("should propagate JS error", async () => {
        const expectedErrorMessage = "Message of expected error";
        const result = await runOnPlatform(async (expectedMessage) => {
            const cc = await helpers.ccInit();

            try {
                await cc.transaction(async () => {
                    throw new Error(expectedMessage);
                });
                throw new Error("Expected transaction to throw");
            } catch (err) {
                return Error.isError(err) && err.message;
            }
        }, expectedErrorMessage);

        expect(result).to.equal(expectedErrorMessage);
    });

    it("should throw error when using invalid context", async () => {
        const result = await runOnPlatform(async () => {
            const CoreCryptoError = ccModule.CoreCryptoError;
            const MlsError = ccModule.MlsError;
            const cc = await helpers.ccInit();

            let context: CoreCryptoContext | null = null;
            await cc.transaction(async (ctx) => {
                context = ctx;
            });

            try {
                await context!.getKeyPackages();
            } catch (err) {
                const e = err as { context?: { context?: { msg?: string } } };
                return {
                    isCorrectInstance:
                        CoreCryptoError.Mls.instanceOf(e) &&
                        MlsError.Other.instanceOf(e.inner.mlsError),
                    message:
                        CoreCryptoError.Mls.instanceOf(e) &&
                        MlsError.Other.instanceOf(e.inner.mlsError) &&
                        e.inner.mlsError.inner.msg,
                };
            }
            throw new Error("Expected getKeyPackages to throw");
        });
        expect(result.isCorrectInstance).to.equal(true);
        expect(result.message).to.equal(
            "This transaction context has already been finished and can no longer be used."
        );
    });

    it("should roll back transaction after error", async () => {
        const error = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();
            const basicCredentialType = ccModule.CredentialType.Basic;
            const conversationId = new ccModule.ConversationId(
                new TextEncoder().encode("testConversation")
            );
            const CoreCryptoError = ccModule.CoreCryptoError;
            const MlsError = ccModule.MlsError;

            const [credentialRef] = await cc.findCredentials({
                credentialType: basicCredentialType,
            });
            const expectedError = new Error("Message of expected error", {
                cause: "This is expected!",
            });
            let thrownError;
            try {
                await cc.transaction(async (ctx) => {
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
                await ctx.createConversation(conversationId, credentialRef!);
            });
            try {
                await cc.transaction(async (ctx) => {
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
        expect(error.message).to.equal("MlsError.ConversationAlreadyExists");
    });
});
