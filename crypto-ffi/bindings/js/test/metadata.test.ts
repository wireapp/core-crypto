import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils.js";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("metadata", () => {
    it("metadata can be retrieved and contains key 'gitDescribe'", async () => {
        await expect(
            browser.execute(async () =>
                window.ccModule.buildMetadata().toJSON()
            )
        ).resolves.toMatchObject({ gitDescribe: expect.anything() });
    });

    it("version can be retrieved and is a semantic version number", async () => {
        await expect(
            browser.execute(async () => window.ccModule.version())
        ).resolves.toMatch(
            RegExp(
                // Regex for matching semantic versions from https://semver.org
                "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$"
            )
        );
    });
});
