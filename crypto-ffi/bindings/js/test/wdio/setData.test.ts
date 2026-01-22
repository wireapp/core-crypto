import { browser, expect } from "@wdio/globals";
import { ccInit, setup, teardown } from "./utils";
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
        const alice = crypto.randomUUID();

        await ccInit(alice);

        const result = await browser.execute(
            async (clientName, text) => {
                const cc = window.ensureCcDefined(clientName);
                const encoder = new TextEncoder();
                const data = encoder.encode(text);
                let dbResultBeforeSet: ArrayBuffer | undefined;
                await cc.newTransaction(async (ctx) => {
                    dbResultBeforeSet = await ctx.getData();
                    await ctx.setData(data.buffer);
                });
                const dbResultAfterSet = await cc.newTransaction(
                    async (ctx) => {
                        return await ctx.getData();
                    }
                );
                const decoder = new TextDecoder();
                return {
                    beforeSet: dbResultBeforeSet,
                    afterSet: decoder.decode(dbResultAfterSet),
                };
            },
            alice,
            text
        );

        expect(result.beforeSet).toBeUndefined();
        expect(result.afterSet).toBe(text);
    });
});
