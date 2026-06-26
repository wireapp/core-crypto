import { setup, teardown, runOnPlatform } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("initialization", () => {
    it("should succeed", async () => {
        await runOnPlatform(async () => {
            await helpers.ccInit();
        });
    });
});
