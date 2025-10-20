import { browser, expect } from "@wdio/globals";
import { ccInit, createConversation, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import {
    ConversationId,
    type CommitBundle,
    type CoreCryptoRichError,
} from "../../src/CoreCrypto";
import { ErrorType } from "../../src/CoreCryptoError";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("core crypto errors", () => {
    it("should build correctly when constructed manually", async () => {
        const alice = crypto.randomUUID();
        await ccInit(alice);
        const result = await browser.execute(async () => {
            const CoreCryptoError = window.ccModule.CoreCryptoError;
            const ErrorType = window.ccModule.ErrorType;
            const ProteusErrorType = window.ccModule.ProteusErrorType;
            const isProteusSessionNotFoundError =
                window.ccModule.isProteusSessionNotFoundError;
            const richErrorJSON: CoreCryptoRichError<ErrorType.Proteus> = {
                error_name: "ErrorTest",
                message: "Hello world",
                error_stack: ["test"],
                type: ErrorType.Proteus,
                context: {
                    type: ProteusErrorType.SessionNotFound,
                    context: {
                        errorCode: 102,
                    },
                },
            };

            const testStr = JSON.stringify(richErrorJSON);

            const e = new Error(testStr);
            const ccErr = CoreCryptoError.fromStdError(e);
            const ccErr2 = CoreCryptoError.build(e.message);

            return {
                errorNamesAreIdentical:
                    ccErr.name === ccErr2.name && ccErr.name === "ErrorTest",
                proteusErrorCodeIsCorrect:
                    isProteusSessionNotFoundError(ccErr) &&
                    isProteusSessionNotFoundError(ccErr2) &&
                    ccErr.context.context.errorCode === 102,
            };
        });
        expect(result.errorNamesAreIdentical).toBe(true);
        expect(result.proteusErrorCodeIsCorrect).toBe(true);
    });

    it("should build correctly when constructed by cc", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await createConversation(alice, convId);

        const result = await browser.execute(
            async (clientName, convId) => {
                const cc = window.ensureCcDefined(clientName);

                const conversationIdBuffer = new TextEncoder().encode(convId).buffer
                const conversationId = new window.ccModule.ConversationId(
                    conversationIdBuffer
                );
                const isMlsConversationAlreadyExistsError =
                    window.ccModule.isMlsConversationAlreadyExistsError;
                const CoreCryptoError = window.ccModule.CoreCryptoError;

                try {
                    await cc.transaction(async (cx) => {
                        await cx.createConversation(
                            conversationId,
                            window.ccModule.CredentialType.Basic
                        );
                    });
                    return {
                        errorWasThrown: false,
                    };
                } catch (err) {
                    if (isMlsConversationAlreadyExistsError(err)) {
                        const conversationIdFromError =
                            new Uint8Array(err.context.context.conversationId);
                        const errorSerialized = JSON.stringify(err);
                        const standardError = new Error(errorSerialized);
                        const errorDeserialized =
                        CoreCryptoError.fromStdError(standardError);
                        return {
                            errorWasThrown: true,
                            isCorrectInstance: true,
                            errorTypeSurvivesSerialization:
                                isMlsConversationAlreadyExistsError(
                                    errorDeserialized
                                ),
                            errorConvIdMatches:
                                JSON.stringify(conversationIdFromError) ===
                                JSON.stringify(
                                    new Uint8Array(conversationIdBuffer)
                                ),
                        };
                    } else {
                        return {
                            errorWasThrown: true,
                            isCorrectInstance: false,
                            errorTypeSurvivesSerialization: false,
                            stackExsists: false,
                            errorConvIdMatches: false,
                        };
                    }
                }
            },
            alice,
            convId
        );
        expect(result.errorWasThrown).toBe(true);
        expect(result.isCorrectInstance).toBe(true);
        expect(result.errorTypeSurvivesSerialization).toBe(true);
        expect(result.errorConvIdMatches).toBe(true);
    });

    it("should be correct when message rejected", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await createConversation(alice, convId);

        const result = await browser.execute(
            async (clientName, convId) => {
                const cc = window.ensureCcDefined(clientName);

                window.deliveryService = {
                    ...window.deliveryService,
                    ...{
                        async sendCommitBundle(_: CommitBundle) {
                            return { abort: { reason: "just testing" } };
                        },
                    },
                };

                cc.provideTransport(window.deliveryService);

                const conversationId = new window.ccModule.ConversationId(
                    new TextEncoder().encode(convId)
                );
                const isMlsMessageRejectedError =
                    window.ccModule.isMlsMessageRejectedError;

                try {
                    await cc.transaction(async (cx) => {
                        await cx.updateKeyingMaterial(conversationId);
                    });
                    return {
                        errorWasThrown: false,
                    };
                } catch (err) {
                    return isMlsMessageRejectedError(err)
                        ? {
                              errorWasThrown: true,
                              errorTypeAndReasonMatch:
                                  "just testing" === err.context.context.reason,
                          }
                        : {
                              errorWasThrown: true,
                              errorTypeAndReasonMatch: false,
                          };
                }
            },
            alice,
            convId
        );

        expect(result.errorWasThrown).toBe(true);
        expect(result.errorTypeAndReasonMatch).toBe(true);
    });
});

it("should build correctly when constructed by wasm bindgen", async () => {
    const alice = crypto.randomUUID();
    const convId = crypto.randomUUID();
    await ccInit(alice);
    const result = await browser.execute(
        async (clientName, convId) => {
            const cc = window.ensureCcDefined(clientName);
            const CoreCryptoError = window.ccModule.CoreCryptoError;

            try {
                await cc.transaction(async (cx) => {
                    await cx.createConversation(
                        // pass in a string argument instead of a `ConversationId` instance
                        convId as unknown as ConversationId,
                        window.ccModule.CredentialType.Basic
                    );
                });
                return {
                    errorWasThrown: false,
                };
            } catch (err) {
                const ccErr = CoreCryptoError.fromStdError(err as Error);

                const errorSerialized = JSON.stringify(err);
                const standardError = new Error(errorSerialized);
                const errorDeserialized =
                    CoreCryptoError.fromStdError(standardError);
                return {
                    errorWasThrown: true,
                    isCorrectInstance: ccErr instanceof CoreCryptoError,
                    errorTypeSurvivesSerialization:
                        errorDeserialized instanceof CoreCryptoError,
                };
            }
        },
        alice,
        convId
    );

    expect(result.errorWasThrown).toBe(true);
    expect(result.isCorrectInstance).toBe(true);
    expect(result.errorTypeSurvivesSerialization).toBe(true);
});

describe("Error type mapping", () => {
    it("should work for conversation already exists", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await createConversation(alice, convId);

        const expectedErrorMessage = "Conversation already exists";

        await expect(
            createConversation(alice, convId)
            // wdio wraps the error and prepends the original message with
            // the error type as prefix
        ).rejects.toThrow(
            new Error(
                `MlsErrorConversationAlreadyExists: ${expectedErrorMessage}`
            )
        );
    });
});
