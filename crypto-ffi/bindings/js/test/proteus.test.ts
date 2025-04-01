import { browser, expect } from "@wdio/globals";
import {
    ALICE_ID,
    BOB_ID,
    newProteusSessionFromMessage,
    newProteusSessionFromPrekey,
    proteusInit,
    SESSION_ID,
    setup,
    teardown,
} from "./utils.js";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
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
