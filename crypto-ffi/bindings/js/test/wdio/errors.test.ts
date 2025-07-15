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
import {
    ConversationId,
    CoreCryptoError,
    type CoreCryptoRichError,
} from "../../src/CoreCrypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("core crypto errors", () => {
    it("should build correctly when constructed manually", async () => {
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

    it("should build correctly when constructed by cc", async () => {
        await ccInit(ALICE_ID);
        await createConversation(ALICE_ID, CONV_ID);

        const result = await browser.execute(
            async (clientName, convId) => {
                const cc = window.ensureCcDefined(clientName);
                const conversationId = new window.ccModule.ConversationId(
                    new TextEncoder().encode(convId)
                );
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
            ALICE_ID,
            CONV_ID
        );

        expect(result.errorWasThrown).toBe(true);
        expect(result.isCorrectInstance).toBe(true);
        expect(result.errorTypeSurvivesSerialization).toBe(true);
    });
});

it("should build correctly when constructed by wasm bindgen", async () => {
    await ccInit(ALICE_ID);
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
        ALICE_ID,
        CONV_ID
    );

    expect(result.errorWasThrown).toBe(true);
    expect(result.isCorrectInstance).toBe(true);
    expect(result.errorTypeSurvivesSerialization).toBe(true);
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
        ).rejects.toThrow(
            new Error(
                `MlsErrorConversationAlreadyExists: ${expectedErrorMessage}`
            )
        );
    });
});
