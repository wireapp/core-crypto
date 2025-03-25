import { browser, expect } from "@wdio/globals";
import {
    ALICE_ID,
    ccInit,
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
