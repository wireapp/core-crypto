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


describe("set_data()", () => {
    it("should persist data to DB", async () => {
        const text = "my message processing checkpoint";

        await ccInit(ALICE_ID);

        const result = await browser.execute(
            async (clientName, text) => {
                const cc = window.ensureCcDefined(clientName);
                const encoder = new TextEncoder();
                const data = encoder.encode(text);
                let dbResultBeforeSet = null;
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
            },
            ALICE_ID,
            text
        );

        expect(result.beforeSet).toBeUndefined();
        expect(result.afterSet).toBe(text);
    });
});
