import { describe, expect, test } from "bun:test";
import { buildMetadata } from "@wireapp/core-crypto/native";

describe("native package output", () => {
    test("package export loads the platform addon", async () => {
        expect(buildMetadata()).toHaveProperty("gitDescribe");
    });
});
