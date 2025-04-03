import { ccInit, setup, teardown } from "./utils.js";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("initialization", () => {
    it("should succeed", async () => {
        await ccInit("foo");
    });
});
