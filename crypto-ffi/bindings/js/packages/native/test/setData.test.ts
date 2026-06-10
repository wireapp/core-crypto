import { ccInit, setup, teardown } from "./utils";
import { test, expect, afterEach, beforeEach, describe } from "bun:test";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("set_data()", () => {
    test("should persist data to DB", async () => {
        const text = "my message processing checkpoint";
        const cc = await ccInit();
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

        expect(dbResultBeforeSet).toBeUndefined();
        expect(decoder.decode(dbResultAfterSet)).toBe(text);
    });
});
