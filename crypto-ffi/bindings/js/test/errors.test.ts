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
import { CoreCryptoError, type CoreCryptoRichError } from "../src/CoreCrypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
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
