import { setup, teardown } from "./utils";
import { afterEach, test, beforeEach, describe, expect } from "bun:test";
import { buildMetadata, version } from "../../src/CoreCrypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("metadata", () => {
    test("metadata can be retrieved and contains key 'gitDescribe'", async () => {
        expect(buildMetadata().toJSON()).toMatchObject({
            gitDescribe: expect.anything(),
        });
    });

    test("version can be retrieved and is a semantic version number", async () => {
        expect(version()).toMatch(
            RegExp(
                // Regex for matching semantic versions from https://semver.org
                "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$"
            )
        );
    });
});
