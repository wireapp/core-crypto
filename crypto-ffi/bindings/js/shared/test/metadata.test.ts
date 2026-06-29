import { runOnPlatform, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { expect } from "chai";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("metadata", () => {
    it("metadata can be retrieved and contains key 'gitDescribe'", async () => {
        const result = await runOnPlatform(async () =>
            ccModule.buildMetadata()
        );
        expect(result).to.haveOwnProperty("gitDescribe");
    });

    it("version can be retrieved and is a semantic version number", async () => {
        const result = await runOnPlatform(async () => ccModule.version());

        expect(result).to.match(
            RegExp(
                // Regex for matching semantic versions from https://semver.org
                "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$"
            )
        );
    });
});
