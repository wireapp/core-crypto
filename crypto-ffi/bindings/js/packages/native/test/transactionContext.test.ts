import { ccInit, setup, teardown } from "./utils";
import { test, expect, afterEach, beforeEach, describe } from "bun:test";
import {
    ConversationId,
    CoreCryptoContext,
    CoreCryptoError,
    CredentialType,
    MlsError,
} from "@wireapp/core-crypto/native";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("transaction context", () => {
    test("should propagate JS error", async () => {
        const expectedErrorMessage = "Message of expected error";
        const cc = await ccInit();
        expect(
            cc.transaction(async () => {
                throw new Error(expectedErrorMessage);
            })
        ).rejects.toThrow(expectedErrorMessage);
    });

    test("should throw error when using invalid context", async () => {
        const cc = await ccInit();

        let context: CoreCryptoContext | null = null;
        await cc.transaction(async (ctx) => {
            context = ctx;
        });

        try {
            await context!.getKeyPackages();
        } catch (err) {
            expect(CoreCryptoError.Mls.instanceOf(err)).toBeTrue();
            if (!CoreCryptoError.Mls.instanceOf(err)) {
                throw new Error("Expected CoreCryptoError.Mls", { cause: err });
            }
            const mlsError = err.inner.mlsError;
            expect(MlsError.Other.instanceOf(mlsError)).toBeTrue();
            if (!MlsError.Other.instanceOf(mlsError)) {
                throw new Error("Expected MlsError.Other", { cause: err });
            }
            expect(mlsError.inner.msg).toBe(
                "This transaction context has already been finished and can no longer be used."
            );
        }
    });

    test("should roll back transaction after error", async () => {
        const cc = await ccInit();
        const basicCredentialType = CredentialType.Basic;
        const conversationId = new ConversationId(
            new TextEncoder().encode("testConversation")
        );

        const [credentialRef] = await cc.findCredentials({
            credentialType: basicCredentialType,
        });

        expect(
            cc.transaction(async (ctx) => {
                await ctx.createConversation(conversationId, credentialRef!);
                throw new Error("Message of expected error", {
                    cause: "This is expected!",
                });
            })
        ).rejects.toThrow("Message of expected error");

        // This would throw a "Conversation already exists" error, if the above transaction hadn't been rolled back.
        await cc.transaction(async (ctx) => {
            await ctx.createConversation(conversationId, credentialRef!);
        });
        try {
            await cc.transaction(async (ctx) => {
                await ctx.createConversation(conversationId, credentialRef!);
            });
            throw new Error("Expected 'Conversation already exists' error");
        } catch (err) {
            expect(CoreCryptoError.Mls.instanceOf(err)).toBeTrue();
            if (!CoreCryptoError.Mls.instanceOf(err)) {
                throw new Error("Expected CoreCryptoError.Mls", { cause: err });
            }
            const mlsError = err.inner.mlsError;
            expect(
                MlsError.ConversationAlreadyExists.instanceOf(mlsError)
            ).toBeTrue();
        }
    });
});
