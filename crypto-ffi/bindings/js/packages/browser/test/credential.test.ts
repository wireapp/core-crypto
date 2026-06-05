import { browser } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("credentials", () => {
    it("can be checked", async () => {
        const result = await browser.execute(async () => {
            try {
                const cc = await window.helpers.ccInit({
                    withBasicCredential: true,
                    cipherSuite: window.defaultCipherSuite,
                    withPkiEnvironment: true,
                });
                await cc.transaction(async (ctx) => {
                    await ctx.checkCredentials();
                });
                return { success: true };
            } catch (err) {
                console.log(JSON.stringify(err));
                return { success: false };
            }
        });
        expect(result.success).toBe(true);
    });
});
