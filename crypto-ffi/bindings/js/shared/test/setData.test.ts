import { runOnPlatform, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { expect } from "chai";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("set_data()", () => {
    it("should persist data to DB", async () => {
        const text = "my message processing checkpoint";
        const result = await runOnPlatform(async (text) => {
            const cc = await helpers.ccInit();
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

        expect(result.beforeSet).to.equal(undefined);
        expect(result.afterSet).to.equal(text);
    });
});
