import { browser, expect } from "@wdio/globals";
import { ccInit, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("client identity", () => {
    it("get client public key should work", async () => {
        const alice = crypto.randomUUID();
        await ccInit(alice);
        const result = await browser.execute(async (clientName) => {
            const cc = window.ensureCcDefined(clientName);
            return (
                await cc.clientPublicKey(
                    window.defaultCipherSuite,
                    window.ccModule.CredentialType.Basic
                )
            ).byteLength;
        }, alice);
        expect(result).toBe(32);
    });

    it("requesting client key packages should work", async () => {
        const alice = crypto.randomUUID();
        await ccInit(alice);
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
        }, alice);
        expect(result).toBe(20);
    });
});
