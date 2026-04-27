import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("client identity", () => {
    it("get client public key should work", async () => {
        const result = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            return (
                await cc.transaction(async (ctx) => {
                    return await ctx.getCredentials();
                })
            )[0]!.publicKeyHash().byteLength;
        });
        await expect(result).toBe(32);
    });

    it("requesting client key package should work", async () => {
        const threwError = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            let threwError = false;
            try {
                const keypackage = await window.helpers.generateKeyPackage(cc);
                keypackage.serialize();
            } catch {
                threwError = true;
            }
            return threwError;
        });
        await expect(threwError).toBe(false);
    });
});
