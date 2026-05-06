import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("set_data()", () => {
    it("should persist data to DB", async () => {
        const text = "my message processing checkpoint";
        const result = await browser.execute(async (text) => {
            const cc = await window.helpers.ccInit();
            const encoder = new TextEncoder();
            const data = encoder.encode(text);
            let dbResultBeforeSet: Uint8Array | undefined;
            await cc.transaction(async (ctx) => {
                dbResultBeforeSet = await ctx.getData();
                await ctx.setData(data);
            });
            const dbResultAfterSet = await cc.transaction(async (ctx) => {
                return await ctx.getData();
            });
            const decoder = new TextDecoder();
            return {
                beforeSet: dbResultBeforeSet,
                afterSet: decoder.decode(dbResultAfterSet),
            };
        }, text);

        await expect(result.beforeSet).toBeUndefined();
        await expect(result.afterSet).toBe(text);
    });
});
