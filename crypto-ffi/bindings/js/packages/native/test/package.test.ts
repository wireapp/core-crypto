import { describe } from "mocha";
import { expect } from "chai";
import { buildMetadata } from "@wireapp/core-crypto/native";

describe("native package output", () => {
    it("package export loads the platform addon", async () => {
        expect(buildMetadata()).to.have.property("gitDescribe");
    });
});
